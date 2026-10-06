"""Hard-deletion of a WaaS account and everything the portal hangs off it.

**This is portal-local and it is irreversible.** It removes the portal's own
record, the stored (Fernet-encrypted) credentials, and every child row. The
Barracuda WaaS tenant and its applications are never touched — nothing here
calls the WaaS API.

Why this module exists rather than a plain ``db.session.delete(account)``:

- SQLite runs with ``PRAGMA foreign_keys = 0``, so the ``ondelete='CASCADE'``
  declared on most child tables never fires.
- Only ``AccountShare`` has an ORM-level ``cascade='all, delete-orphan'``. For
  every other child SQLAlchemy falls back to de-association and emits
  ``UPDATE ... SET account_id = NULL`` against a ``nullable=False`` column,
  which raises ``IntegrityError`` and deletes nothing.

Two children own state outside their own row, and a row-only delete would
orphan it permanently:

- ``ProxySession`` holds four live OS pids (Xvfb, chromium, x11vnc,
  websockify). The only reaper, ``proxy_manager.cleanup_stale_sessions()``,
  works *from these rows* — delete the row and the processes leak forever.
- ``LogPull`` owns ``instance/log_pulls/<id>/`` on disk (78 MB across three
  pulls today; a full pull runs to gigabytes). The established teardown is
  ``PullStore(...).delete_all()`` then delete the row — see
  ``app/routes/admin.py:storage_delete_pull``.

So the order is: refuse if busy → stop processes → one transaction for all the
rows → remove directories only after that transaction commits. Side effects
that cannot be rolled back must never sit inside a transaction that can be.

NOTE: ``User.waas_accounts`` is declared ``cascade='all, delete-orphan'``
(``app/models.py``), so deleting a *user* would ORM-cascade into their accounts
and hit the exact same ``IntegrityError``. No route deletes users today; if one
is ever added it must route through ``delete_waas_account()``.
"""
import logging

from flask_babel import gettext as _
from flask_babel import lazy_gettext as _l

from app import db
from app.models import (
    AccountShare, AppTrafficSnapshot, ConfigSnapshot, FeatureApplication,
    LogPull, ProxySession, ReportRun, ScheduledReport, SecurityMetricSnapshot,
    SiteProfile, TemplateApplication, WaasAccount,
)

logger = logging.getLogger(__name__)

#: Every model with an ``account_id`` pointing at ``waas_accounts.id``, with the
#: label shown in the confirmation dialog. Deliberately hardcoded rather than
#: derived from the mapper registry: this is the blast radius of an irreversible
#: operation, so it should be a list a human wrote down, not one that silently
#: grows when somebody adds a table. ``tests/test_account_deletion.py`` walks the
#: registry and fails if a new child table is missing from here, which gives the
#: safety of reflection without the surprise.
CHILD_MODELS = [
    ('config_snapshots', ConfigSnapshot, _l('Config snapshots')),
    ('proxy_sessions', ProxySession, _l('Browser proxy sessions')),
    ('feature_applications', FeatureApplication, _l('Applied raw configs')),
    ('template_applications', TemplateApplication, _l('Applied templates')),
    ('account_shares', AccountShare, _l('Account shares')),
    ('scheduled_reports', ScheduledReport, _l('Scheduled reports')),
    ('site_profiles', SiteProfile, _l('Site profiles')),
    ('security_metric_snapshots', SecurityMetricSnapshot, _l('Security metric snapshots')),
    ('app_traffic_snapshots', AppTrafficSnapshot, _l('Traffic snapshots')),
    ('log_pulls', LogPull, _l('Log pulls')),
]


def _text(label):
    """Render a lazy label, falling back to English outside a request context.

    ``get_locale`` reads ``session``, so resolving a translation needs a request
    context. The route always has one; a CLI or background caller would not, and
    an untranslated label beats a RuntimeError.
    """
    try:
        return str(label)
    except RuntimeError:
        return label._args[0]


def _scheduled_report_ids(account_id):
    return [row.id for row in ScheduledReport.query
            .filter_by(account_id=account_id)
            .with_entities(ScheduledReport.id).all()]


def account_delete_blockers(account):
    """Reasons this account cannot be deleted right now, as translated strings.

    Mirrors ``admin.storage_delete_pull``'s "cancel it first" refusal. A log
    pull is a long-running greenlet that holds a ``LogPull`` row and writes into
    its directory; deleting underneath it both breaks the greenlet's next commit
    and lets it re-create the directory we just removed.
    """
    blockers = []

    active_pulls = LogPull.query.filter(
        LogPull.account_id == account.id,
        LogPull.status.in_(LogPull.ACTIVE_STATUSES),
    ).count()
    if active_pulls:
        blockers.append(_(
            '%(count)d log pull(s) are still running. Cancel them first.',
            count=active_pulls,
        ))

    active_profiles = SiteProfile.query.filter(
        SiteProfile.account_id == account.id,
        SiteProfile.status.in_((SiteProfile.STATUS_PENDING, SiteProfile.STATUS_PROBING)),
    ).count()
    if active_profiles:
        blockers.append(_(
            '%(count)d site profile(s) are still running. Wait for them to finish.',
            count=active_profiles,
        ))

    return blockers


def account_delete_impact(account):
    """What deleting this account would destroy, for the confirmation dialog.

    Returns a list of ``{'key', 'label', 'count'}`` with the labels already
    translated, so the label-to-model mapping lives here rather than being
    duplicated into a JS literal. Zero-count categories are included; the
    template decides what to show.
    """
    impact = []
    for key, model, label in CHILD_MODELS:
        impact.append({
            'key': key,
            'label': _text(label),
            'count': model.query.filter_by(account_id=account.id).count(),
        })

    report_ids = _scheduled_report_ids(account.id)
    run_count = (ReportRun.query.filter(ReportRun.report_id.in_(report_ids)).count()
                 if report_ids else 0)
    impact.append({'key': 'report_runs', 'label': _text(_l('Report runs')), 'count': run_count})
    return impact


def delete_waas_account(account, instance_path):
    """Delete ``account`` and every row and artifact belonging to it.

    Returns ``{'counts': {table: rows}, 'bytes_freed': int, 'sessions_stopped': int}``.

    Caller must check :func:`account_delete_blockers` first. Commits.
    """
    from app import proxy_manager
    from app.logpull.store import PullStore

    account_id = account.id
    account_name = account.account_name

    # --- Phase 1: irreversible side effects that must happen before the ---
    # --- transaction, because they cannot be rolled back with it.        ---
    sessions_stopped = 0
    for session in ProxySession.query.filter(
        ProxySession.account_id == account_id,
        ProxySession.status.in_(('starting', 'active')),
    ).all():
        try:
            # stop_session() commits on its own, which is exactly why it has to
            # run before we open the delete transaction.
            proxy_manager.stop_session(session.id)
            sessions_stopped += 1
        except Exception as e:  # a dead pid must not block the delete
            logger.warning(f'Account delete: could not stop proxy session {session.id}: {e}')

    # Collect before the rows go — we need the ids to find the directories.
    pull_ids = [row.id for row in LogPull.query
                .filter_by(account_id=account_id)
                .with_entities(LogPull.id).all()]

    # --- Phase 2: one transaction for every row. ---
    counts = {}

    # Grandchildren first. ReportRun has no account_id of its own, and a bulk
    # delete of ScheduledReport bypasses the ORM cascade that would catch it.
    report_ids = _scheduled_report_ids(account_id)
    counts['report_runs'] = (
        ReportRun.query.filter(ReportRun.report_id.in_(report_ids))
        .delete(synchronize_session=False) if report_ids else 0
    )

    # ConfigSnapshot.reverted_from_id is self-referential with ondelete='SET
    # NULL' that the pragma makes inert. config_history always creates the
    # revert snapshot in the same account, so deleting the account's whole set
    # is self-consistent — but nothing enforces that, so null the links first.
    snapshot_ids = [row.id for row in ConfigSnapshot.query
                    .filter_by(account_id=account_id)
                    .with_entities(ConfigSnapshot.id).all()]
    if snapshot_ids:
        ConfigSnapshot.query.filter(
            ConfigSnapshot.reverted_from_id.in_(snapshot_ids)
        ).update({'reverted_from_id': None}, synchronize_session=False)

    for key, model, _label in CHILD_MODELS:
        counts[key] = model.query.filter_by(account_id=account_id).delete(
            synchronize_session=False
        )

    # Core delete rather than db.session.delete(account): the ORM path would
    # walk every lazy='dynamic' backref to null out FKs — the machinery that
    # raised IntegrityError in the first place.
    WaasAccount.query.filter_by(id=account_id).delete(synchronize_session=False)
    db.session.commit()

    # Bulk deletes leave stale objects in the identity map, and g.current_account
    # is resolved on every request.
    db.session.expire_all()

    # --- Phase 3: disk, only now that the rows are definitely gone. ---
    bytes_freed = 0
    for pull_id in pull_ids:
        try:
            bytes_freed += PullStore(instance_path, pull_id).delete_all()
        except Exception as e:
            # Leaked bytes are recoverable from the admin storage page; a failure
            # here must not look like the account survived.
            logger.warning(f'Account delete: could not remove log pull {pull_id} data: {e}')

    # 30s per-account cache in the global search index would otherwise serve a
    # dead account's apps, and SQLite reuses rowids.
    try:
        from app.routes.search import _account_resource_cache
        for cache_key in [k for k in _account_resource_cache if k[0] == account_id]:
            _account_resource_cache.pop(cache_key, None)
    except Exception:  # pragma: no cover — cache shape is an implementation detail
        pass

    logger.info(
        f'Deleted WaaS account {account_id} ("{account_name}"): '
        f'{sum(counts.values())} row(s), {sessions_stopped} proxy session(s) stopped, '
        f'{bytes_freed / 1e6:.1f} MB freed'
    )
    return {'counts': counts, 'bytes_freed': bytes_freed, 'sessions_stopped': sessions_stopped}
