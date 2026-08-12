"""
Report generation, email delivery, and scheduling for WaaS scheduled reports.
"""
import json
import logging
from datetime import datetime, timedelta
from collections import Counter
from flask import render_template
from flask_mail import Message

logger = logging.getLogger(__name__)


def generate_waf_summary(client, time_range='r_7d'):
    """Generate WAF summary: top attacks, top IPs, severity breakdown."""
    try:
        apps_result = client.list_applications()
        apps = apps_result if isinstance(apps_result, list) else apps_result.get('results', apps_result.get('applications', []))
    except Exception as e:
        logger.warning(f'Failed to list apps for WAF summary: {e}')
        apps = []

    all_waf_logs = []
    for app in apps:
        app_name = app.get('name', '') if isinstance(app, dict) else str(app)
        if not app_name:
            continue
        try:
            result = client.get_logs(app_name, quick_range=time_range, page=1, items_per_page=500)
            entries = result.get('results', [])
            waf_entries = [e for e in entries if e.get('LogType') == 'WF']
            all_waf_logs.extend(waf_entries)
        except Exception as e:
            logger.warning(f'Failed to get WAF logs for {app_name}: {e}')

    attack_counter = Counter()
    ip_counter = Counter()
    severity_counter = Counter()
    action_counter = Counter()

    for entry in all_waf_logs:
        attack_counter[entry.get('Attack', 'Unknown')] += 1
        ip_counter[entry.get('ClientIP', 'Unknown')] += 1
        severity_counter[entry.get('Severity', 'Unknown')] += 1
        action_counter[entry.get('Action', 'Unknown')] += 1

    return {
        'total_events': len(all_waf_logs),
        'app_count': len(apps),
        'top_attacks': attack_counter.most_common(10),
        'top_ips': ip_counter.most_common(10),
        'severity_breakdown': dict(severity_counter),
        'action_breakdown': dict(action_counter),
        'time_range': time_range,
        'generated_at': datetime.utcnow().isoformat(),
    }


def generate_access_summary(client, time_range='r_7d'):
    """Generate access summary: request totals, top URLs, status codes."""
    try:
        apps_result = client.list_applications()
        apps = apps_result if isinstance(apps_result, list) else apps_result.get('results', apps_result.get('applications', []))
    except Exception as e:
        logger.warning(f'Failed to list apps for access summary: {e}')
        apps = []

    all_access_logs = []
    for app in apps:
        app_name = app.get('name', '') if isinstance(app, dict) else str(app)
        if not app_name:
            continue
        try:
            result = client.get_logs(app_name, quick_range=time_range, page=1, items_per_page=500)
            entries = result.get('results', [])
            access_entries = [e for e in entries if e.get('LogType') == 'TR']
            all_access_logs.extend(access_entries)
        except Exception as e:
            logger.warning(f'Failed to get access logs for {app_name}: {e}')

    url_counter = Counter()
    status_counter = Counter()
    method_counter = Counter()

    for entry in all_access_logs:
        url_counter[entry.get('URL', 'Unknown')] += 1
        status_counter[str(entry.get('HTTPStatus', 'Unknown'))] += 1
        method_counter[entry.get('Method', 'Unknown')] += 1

    return {
        'total_requests': len(all_access_logs),
        'app_count': len(apps),
        'top_urls': url_counter.most_common(10),
        'status_breakdown': dict(status_counter),
        'method_breakdown': dict(method_counter),
        'time_range': time_range,
        'generated_at': datetime.utcnow().isoformat(),
    }


def generate_security_overview(client):
    """Generate security overview: current config state across apps."""
    try:
        apps_result = client.list_applications()
        apps = apps_result if isinstance(apps_result, list) else apps_result.get('results', apps_result.get('applications', []))
    except Exception as e:
        logger.warning(f'Failed to list apps for security overview: {e}')
        apps = []

    app_configs = []
    for app in apps:
        app_name = app.get('name', '') if isinstance(app, dict) else str(app)
        if not app_name:
            continue
        try:
            config = client.get_security_config(app_name)
            app_configs.append({
                'name': app_name,
                'protection_mode': config.get('protection_mode', 'Unknown'),
                'request_limits': config.get('request_limits', {}),
                'clickjacking_protection': config.get('clickjacking_protection', {}),
                'data_theft_protection': config.get('data_theft_protection', {}),
            })
        except Exception as e:
            logger.warning(f'Failed to get security config for {app_name}: {e}')
            app_configs.append({'name': app_name, 'protection_mode': 'Error', 'error': str(e)})

    protection_modes = Counter(c.get('protection_mode', 'Unknown') for c in app_configs)

    return {
        'app_count': len(apps),
        'app_configs': app_configs,
        'protection_modes': dict(protection_modes),
        'generated_at': datetime.utcnow().isoformat(),
    }


def _time_range_for_frequency(frequency):
    """Map frequency to WaaS API quick_range parameter."""
    return {
        'daily': 'r_24h',
        'weekly': 'r_7d',
        'monthly': 'r_30d',
    }.get(frequency, 'r_7d')


def send_report_email(app, report, summary_data):
    """Render and send report email. Falls back to logging if SMTP unavailable."""
    from app import mail

    report_type_labels = {
        'waf_summary': 'WAF Summary',
        'access_summary': 'Access Summary',
        'security_overview': 'Security Overview',
    }
    report_label = report_type_labels.get(report.report_type, report.report_type)

    subject = f'[WaaS Portal] {report.name} — {report_label}'
    recipients = report.recipients_list

    if not recipients:
        logger.warning(f'Report {report.id} has no recipients, skipping email')
        return 0

    try:
        with app.app_context():
            html_body = render_template(
                f'email/{report.report_type}.html',
                report=report,
                summary=summary_data,
                report_label=report_label,
            )
    except Exception:
        # Fallback to a simple text summary
        html_body = f'<h2>{report.name}</h2><pre>{json.dumps(summary_data, indent=2, default=str)}</pre>'

    try:
        msg = Message(subject=subject, recipients=recipients, html=html_body)
        mail.send(msg)
        logger.info(f'Report email sent to {len(recipients)} recipients for report {report.id}')
        return len(recipients)
    except Exception as e:
        logger.error(f'Failed to send report email for report {report.id}: {e}')
        # Log the summary so it's not lost
        logger.info(f'Report {report.id} summary (email failed): {json.dumps(summary_data, default=str)[:500]}')
        raise


def compute_next_run(report):
    """Calculate next_run_at based on frequency, day_of_week, hour."""
    now = datetime.utcnow()
    hour = report.hour or 8

    if report.frequency == 'daily':
        next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)

    elif report.frequency == 'weekly':
        day = report.day_of_week if report.day_of_week is not None else 0
        next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        days_ahead = day - now.weekday()
        if days_ahead < 0 or (days_ahead == 0 and next_run <= now):
            days_ahead += 7
        next_run += timedelta(days=days_ahead)

    elif report.frequency == 'monthly':
        # Run on the 1st of next month
        if now.month == 12:
            next_run = now.replace(year=now.year + 1, month=1, day=1, hour=hour, minute=0, second=0, microsecond=0)
        else:
            next_run = now.replace(month=now.month + 1, day=1, hour=hour, minute=0, second=0, microsecond=0)
    else:
        next_run = now + timedelta(days=1)

    return next_run


def run_scheduled_reports(app):
    """Query due reports, generate, send, update. Called by scheduler."""
    from app import db
    from app.models import ScheduledReport, ReportRun
    from app.waas_client import WaasClient

    with app.app_context():
        now = datetime.utcnow()
        due_reports = ScheduledReport.query.filter(
            ScheduledReport.is_active == True,
            ScheduledReport.next_run_at <= now
        ).all()

        if not due_reports:
            return

        logger.info(f'Running {len(due_reports)} scheduled reports')

        for report in due_reports:
            try:
                # Get the account and create client
                account = report.account
                if not account or not account.is_active:
                    raise Exception('Account inactive or not found')

                client = WaasClient.from_account(account)
                time_range = _time_range_for_frequency(report.frequency)

                # Generate report
                if report.report_type == 'waf_summary':
                    summary = generate_waf_summary(client, time_range)
                elif report.report_type == 'access_summary':
                    summary = generate_access_summary(client, time_range)
                elif report.report_type == 'security_overview':
                    summary = generate_security_overview(client)
                else:
                    raise Exception(f'Unknown report type: {report.report_type}')

                # Send email
                try:
                    recipient_count = send_report_email(app, report, summary)
                except Exception as email_error:
                    recipient_count = 0
                    logger.warning(f'Email failed for report {report.id}, recording run anyway: {email_error}')

                # Record run
                run = ReportRun(
                    report_id=report.id,
                    status='success',
                    recipient_count=recipient_count,
                    summary=json.dumps(summary, default=str),
                )
                db.session.add(run)

                report.last_run_at = now
                report.last_status = 'success'
                report.last_error = None
                report.next_run_at = compute_next_run(report)
                db.session.commit()

                # Create in-app notification if user preference allows it
                try:
                    from app.models import Notification, User
                    owner = db.session.get(User, report.user_id)
                    if owner and (owner.notify_report_inapp is None or owner.notify_report_inapp):
                        report_label = {'waf_summary': 'WAF Summary', 'access_summary': 'Access Summary', 'security_overview': 'Security Overview'}.get(report.report_type, report.report_type)
                        Notification.create(
                            user_id=report.user_id,
                            type='report',
                            title=f'Report ready: {report.name}',
                            message=f'{report_label} completed successfully.',
                            link='/reports/',
                        )
                except Exception as notif_err:
                    logger.warning(f'Failed to create notification for report {report.id}: {notif_err}')

                logger.info(f'Report {report.id} completed successfully')

            except Exception as e:
                logger.error(f'Report {report.id} failed: {e}')

                run = ReportRun(
                    report_id=report.id,
                    status='failed',
                    recipient_count=0,
                    error_message=str(e),
                )
                db.session.add(run)

                report.last_run_at = now
                report.last_status = 'failed'
                report.last_error = str(e)
                report.next_run_at = compute_next_run(report)
                db.session.commit()
