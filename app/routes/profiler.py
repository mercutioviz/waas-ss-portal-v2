"""Web App Profiler + guided new-site wizard.

Entry points:
    GET  /profiler/new?account_id=N   — URL-entry form
    POST /profiler/new                 — kicks off the async probe
    GET  /profiler/<id>/watch          — progress page (SocketIO room = session_id)
    GET  /profiler/<id>/results        — pre-filled create-application form
                                          with per-field rationale + advisories

The recommender output is JSON on the SiteProfile row; the results page
merges it into an ApplicationCreateForm instance for review. Submitting
that form POSTs to the existing /applications/<account_id>/create route.
"""

import uuid
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_babel import gettext as _
from flask_login import current_user, login_required

from app import db, limiter, socketio
from app.background_tasks import run_site_profile
from app.forms import ApplicationCreateForm, ProfileUrlForm
from app.models import SiteProfile, WaasAccount

bp = Blueprint('profiler', __name__, url_prefix='/profiler')

COOLDOWN_SECONDS = 30


def _get_account_for_user(account_id: int) -> WaasAccount | None:
    """Return the account if the current user owns it (or has access), else None.

    Uses the same ownership rule the applications module uses — direct owner
    only. Sharing is out-of-scope for the profiler for now.
    """
    return WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first()


def _v2_capable_accounts_for_user() -> list[WaasAccount]:
    """All active accounts the current user owns that can be used to create
    an application at the end of the wizard (v2 email+password required)."""
    owned = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    return [a for a in owned if a.has_v2_credentials]


@bp.route('/new', methods=['GET', 'POST'])
@login_required
@limiter.limit('5 per minute', methods=['POST'])
def new_profile():
    account_id = request.values.get('account_id', type=int)

    # No account chosen yet — pick one, auto-forward if only one option, or
    # explain how to enable the feature if none.
    if not account_id:
        v2_accounts = _v2_capable_accounts_for_user()
        if not v2_accounts:
            return render_template('profiler/pick_account.html', accounts=[])
        if len(v2_accounts) == 1:
            return redirect(url_for('profiler.new_profile', account_id=v2_accounts[0].id))
        return render_template('profiler/pick_account.html', accounts=v2_accounts)

    account = _get_account_for_user(account_id)
    if not account:
        abort(404)

    if not account.has_v2_credentials:
        # Instead of bouncing to a page with no context, render the picker
        # so the user can see their other options (if any) inline.
        flash(
            _('Account "%(name)s" needs v2 credentials (email + password) '
              'before the profiler can create an application under it.',
              name=account.account_name),
            'warning',
        )
        return redirect(url_for('profiler.new_profile'))

    form = ProfileUrlForm()

    if form.validate_on_submit():
        target = form.target_url.data.strip()
        if '://' not in target:
            target = 'https://' + target

        # Cooldown: same target from same user within COOLDOWN_SECONDS.
        cutoff = datetime.utcnow() - timedelta(seconds=COOLDOWN_SECONDS)
        recent = SiteProfile.query.filter(
            SiteProfile.user_id == current_user.id,
            SiteProfile.target_url == target,
            SiteProfile.created_at >= cutoff,
        ).order_by(SiteProfile.created_at.desc()).first()
        if recent is not None:
            flash(
                _('You just profiled that URL — showing the existing result. '
                  'Wait %(secs)s seconds to re-run.', secs=COOLDOWN_SECONDS),
                'info',
            )
            return redirect(url_for('profiler.watch_profile', profile_id=recent.id))

        session_id = str(uuid.uuid4())
        profile = SiteProfile(
            user_id=current_user.id,
            account_id=account.id,
            target_url=target,
            status=SiteProfile.STATUS_PENDING,
            session_id=session_id,
        )
        db.session.add(profile)
        db.session.commit()

        # Capture the app object here, in request context, before spawning the
        # greenlet — same pattern as the clone flow (routes/applications.py:824).
        real_app = current_app._get_current_object()
        socketio.start_background_task(
            run_site_profile, real_app, profile.id, session_id, target,
        )

        return redirect(url_for('profiler.watch_profile', profile_id=profile.id))

    return render_template('profiler/new.html', form=form, account=account)


@bp.route('/<int:profile_id>/watch')
@login_required
def watch_profile(profile_id: int):
    profile = SiteProfile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()

    # If the probe already finished (e.g., user hit refresh), skip straight to results.
    if profile.status == SiteProfile.STATUS_COMPLETE:
        return redirect(url_for('profiler.profile_results', profile_id=profile.id))
    if profile.status == SiteProfile.STATUS_ERROR:
        flash(_('Profile failed: %(err)s', err=profile.error_message or 'unknown error'), 'danger')
        return redirect(url_for('profiler.new_profile', account_id=profile.account_id))

    from app.profiler.probe import PROBE_STEPS
    return render_template(
        'profiler/watch.html',
        profile=profile,
        steps=PROBE_STEPS,
        session_id=profile.session_id,
    )


@bp.route('/<int:profile_id>/results')
@login_required
def profile_results(profile_id: int):
    profile = SiteProfile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
    if profile.status != SiteProfile.STATUS_COMPLETE:
        # Still probing → send back to watch; otherwise error was handled there.
        return redirect(url_for('profiler.watch_profile', profile_id=profile.id))

    recommendation = profile.recommendation or {'form_fields': {}, 'advisories': []}
    form_fields = recommendation.get('form_fields', {})
    advisories = recommendation.get('advisories', [])

    # Pre-fill the existing ApplicationCreateForm with the recommendation.
    form = ApplicationCreateForm(data={
        key: fld['value'] for key, fld in form_fields.items()
    })

    return render_template(
        'profiler/results.html',
        profile=profile,
        form=form,
        form_fields=form_fields,
        advisories=advisories,
        account=profile.account,
    )
