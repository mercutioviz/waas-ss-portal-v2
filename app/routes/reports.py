"""
Scheduled reports blueprint — CRUD, run-now, history.
"""
import json
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app import db
from app.models import ScheduledReport, ReportRun, AuditLog, get_user_accounts, get_account_for_user, can_write
from app.forms import ScheduledReportForm
from app.report_service import compute_next_run
from app import limiter

bp = Blueprint('reports', __name__, url_prefix='/reports')


def _populate_account_choices(form):
    """Populate the account_id select field with user's accounts."""
    accounts = get_user_accounts(current_user)
    form.account_id.choices = [(a.id, a.account_name) for a in accounts]


@bp.route('/')
@login_required
def list_reports():
    """List user's scheduled reports."""
    reports = ScheduledReport.query.filter_by(user_id=current_user.id)\
        .order_by(ScheduledReport.updated_at.desc()).all()
    return render_template('reports/list.html', reports=reports)


@bp.route('/add', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def add_report():
    """Create a new scheduled report."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to create reports.'), 'danger')
        return redirect(url_for('reports.list_reports'))

    form = ScheduledReportForm()
    _populate_account_choices(form)

    if form.validate_on_submit():
        # Parse recipients
        recipients = [r.strip() for r in form.recipients.data.split(',') if r.strip()]
        if not recipients:
            flash(_('At least one recipient email is required.'), 'warning')
            return render_template('reports/add.html', form=form)

        day_of_week = int(form.day_of_week.data) if form.day_of_week.data else None

        report = ScheduledReport(
            user_id=current_user.id,
            name=form.name.data.strip(),
            account_id=form.account_id.data,
            report_type=form.report_type.data,
            frequency=form.frequency.data,
            day_of_week=day_of_week,
            hour=form.hour.data,
            is_active=True,
        )
        report.recipients_list = recipients
        report.next_run_at = compute_next_run(report)

        db.session.add(report)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='report_create',
            resource_type='scheduled_report',
            resource_id=report.id,
            details=f'Created scheduled report: {report.name}',
            ip_address=request.remote_addr
        )

        flash(_('Report "%(name)s" created.', name=report.name), 'success')
        return redirect(url_for('reports.view_report', report_id=report.id))

    return render_template('reports/add.html', form=form)


@bp.route('/<int:report_id>')
@login_required
def view_report(report_id):
    """View report details + run history."""
    report = ScheduledReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    runs = ReportRun.query.filter_by(report_id=report.id)\
        .order_by(ReportRun.run_at.desc()).limit(20).all()
    return render_template('reports/view.html', report=report, runs=runs)


@bp.route('/<int:report_id>/edit', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute", methods=["POST"])
def edit_report(report_id):
    """Edit a scheduled report."""
    report = ScheduledReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()

    form = ScheduledReportForm(obj=report)
    _populate_account_choices(form)

    if request.method == 'GET':
        form.recipients.data = ', '.join(report.recipients_list)
        form.day_of_week.data = str(report.day_of_week) if report.day_of_week is not None else ''

    if form.validate_on_submit():
        recipients = [r.strip() for r in form.recipients.data.split(',') if r.strip()]

        report.name = form.name.data.strip()
        report.account_id = form.account_id.data
        report.report_type = form.report_type.data
        report.frequency = form.frequency.data
        report.day_of_week = int(form.day_of_week.data) if form.day_of_week.data else None
        report.hour = form.hour.data
        report.recipients_list = recipients
        report.next_run_at = compute_next_run(report)

        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='report_edit',
            resource_type='scheduled_report',
            resource_id=report.id,
            details=f'Edited scheduled report: {report.name}',
            ip_address=request.remote_addr
        )

        flash(_('Report "%(name)s" updated.', name=report.name), 'success')
        return redirect(url_for('reports.view_report', report_id=report.id))

    return render_template('reports/edit.html', form=form, report=report)


@bp.route('/<int:report_id>/delete', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_report(report_id):
    """Delete a scheduled report."""
    report = ScheduledReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    report_name = report.name

    AuditLog.log(
        user_id=current_user.id,
        action='report_delete',
        resource_type='scheduled_report',
        resource_id=report.id,
        details=f'Deleted scheduled report: {report_name}',
        ip_address=request.remote_addr
    )

    db.session.delete(report)
    db.session.commit()

    flash(_('Report "%(name)s" deleted.', name=report_name), 'success')
    return redirect(url_for('reports.list_reports'))


@bp.route('/<int:report_id>/toggle', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def toggle_report(report_id):
    """Toggle report active/inactive."""
    report = ScheduledReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    report.is_active = not report.is_active
    if report.is_active:
        report.next_run_at = compute_next_run(report)
    db.session.commit()

    status = _('activated') if report.is_active else _('deactivated')
    flash(_('Report "%(name)s" %(status)s.', name=report.name, status=status), 'success')
    return redirect(url_for('reports.view_report', report_id=report.id))


@bp.route('/<int:report_id>/run-now', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def run_now(report_id):
    """Trigger an immediate report run."""
    from flask import current_app
    from app.report_service import (
        generate_waf_summary, generate_access_summary,
        generate_security_overview, send_report_email,
        _time_range_for_frequency,
    )
    from app.waas_client import WaasClient

    report = ScheduledReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()

    try:
        account = report.account
        if not account or not account.is_active:
            raise Exception(_('Account inactive or not found'))

        client = WaasClient.from_account(account)
        time_range = _time_range_for_frequency(report.frequency)

        if report.report_type == 'waf_summary':
            summary = generate_waf_summary(client, time_range)
        elif report.report_type == 'access_summary':
            summary = generate_access_summary(client, time_range)
        elif report.report_type == 'security_overview':
            summary = generate_security_overview(client)
        else:
            raise Exception(f'Unknown report type: {report.report_type}')

        # Try to send email
        try:
            recipient_count = send_report_email(current_app._get_current_object(), report, summary)
        except Exception as email_error:
            recipient_count = 0
            flash(_('Report generated but email failed: %(error)s', error=str(email_error)), 'warning')

        run = ReportRun(
            report_id=report.id,
            status='success',
            recipient_count=recipient_count,
            summary=json.dumps(summary, default=str),
        )
        db.session.add(run)

        report.last_run_at = datetime.utcnow()
        report.last_status = 'success'
        report.last_error = None
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='report_run_now',
            resource_type='scheduled_report',
            resource_id=report.id,
            details=f'Manual run of report: {report.name}',
            ip_address=request.remote_addr
        )

        flash(_('Report "%(name)s" executed successfully.', name=report.name), 'success')

    except Exception as e:
        run = ReportRun(
            report_id=report.id,
            status='failed',
            recipient_count=0,
            error_message=str(e),
        )
        db.session.add(run)

        report.last_run_at = datetime.utcnow()
        report.last_status = 'failed'
        report.last_error = str(e)
        db.session.commit()

        flash(_('Report execution failed: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('reports.view_report', report_id=report.id))


@bp.route('/<int:report_id>/history/<int:run_id>')
@login_required
def run_detail(report_id, run_id):
    """View a specific report run."""
    report = ScheduledReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    run = ReportRun.query.filter_by(id=run_id, report_id=report.id).first_or_404()
    return render_template('reports/run_detail.html', report=report, run=run)
