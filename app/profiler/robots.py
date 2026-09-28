"""Parse robots.txt into a structured report.

Pure function of the fetched text — no I/O. Mirrors the shape of
cache_analysis.py / security_headers.py: this module only observes and parses;
the recommender turns the observations into advisories.

The parser is deliberately lenient. robots.txt has no enforcing authority, so
real-world files are full of stray syntax, vendor extensions, and typos. Every
unrecognized line is collected rather than raised on.
"""

import re
from typing import Optional

from app.profiler.schemas import RobotsGroup, RobotsReport

# Caps — this report is serialized into SiteProfile.profile_data, so a
# pathological robots.txt must not blow up the stored JSON blob.
MAX_RULES_PER_GROUP = 200
MAX_GROUPS = 50
MAX_SITEMAPS = 25
MAX_SENSITIVE = 25
MAX_UNKNOWN = 20

# Disallowed paths matching these markers get called out: the site owner has
# told us which paths they consider off-limits, and robots.txt is public, so
# the same list is a roadmap for anyone probing the site.
#
# Deliberately tight. Paths like /login, /search, /cart, /account and /api are
# routinely disallowed for crawl-budget reasons rather than secrecy — flagging
# them would bury the real findings and train users to skim past the advisory.
SENSITIVE_PATH_MARKERS = (
    # Admin surfaces
    'admin', 'wp-admin', 'administrator', 'phpmyadmin', 'cpanel', 'webmail',
    # VCS / config leakage
    '.git', '.svn', '.hg', '.env', 'config', 'phpinfo',
    # Backups and dumps
    'backup', 'backups', 'dump', 'sqldump',
    # Internal-only surface
    'cgi-bin', 'internal', 'staging', 'private', 'secret', 'secrets',
    'credentials',
)

_RULE_FIELDS = ('disallow', 'allow')


def _strip_comment(line: str) -> str:
    """Remove a trailing `#` comment. robots.txt has no escaping, so the first
    `#` always starts a comment."""
    idx = line.find('#')
    return line if idx < 0 else line[:idx]


def _matches_marker(path: str, marker: str) -> bool:
    """Segment-aware containment check.

    Plain substring matching is too loose — `'admin' in '/badminton/'` is True.
    Requiring a path separator (or string boundary) on both sides keeps
    `/wp-admin/` and `/admin` matching while rejecting `/badminton/`.
    """
    pattern = r'(^|[/_.\-])' + re.escape(marker) + r'([/_.\-]|$)'
    return re.search(pattern, path) is not None


def _is_sensitive(path: str) -> bool:
    lower = path.lower()
    return any(_matches_marker(lower, m) for m in SENSITIVE_PATH_MARKERS)


def _parse_float(raw: str) -> Optional[float]:
    try:
        return float(raw.strip())
    except ValueError:
        return None


def parse(text: str, *, truncated: bool = False) -> RobotsReport:
    """Parse robots.txt `text` into a RobotsReport.

    `truncated` records that the raw copy stored for display was cut; parsing
    always runs over the full text handed in.
    """
    report = RobotsReport(present=True, truncated=truncated)
    if not text:
        return report

    # Strip a UTF-8 BOM — servers that hand-edit robots.txt on Windows are common.
    text = text.lstrip('﻿')

    groups: list[RobotsGroup] = []
    current: Optional[RobotsGroup] = None
    # Consecutive User-agent lines share one group; a rule line closes the
    # header, so the next User-agent starts a fresh group.
    accepting_agents = False

    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        if not line or ':' not in line:
            continue

        field, _, value = line.partition(':')
        field = field.strip().lower()
        value = value.strip()

        if field == 'user-agent':
            if not value:
                continue
            if current is None or not accepting_agents:
                if len(groups) >= MAX_GROUPS:
                    break
                current = RobotsGroup()
                groups.append(current)
                accepting_agents = True
            current.user_agents.append(value)

        elif field in _RULE_FIELDS:
            if current is None:
                # Rules before any User-agent line. Technically invalid; most
                # crawlers treat them as applying to everyone, so we do too.
                current = RobotsGroup(user_agents=['*'])
                groups.append(current)
            accepting_agents = False
            # A bare `Disallow:` means "allow everything" — it carries no path,
            # so there is nothing to record.
            if not value:
                continue
            target = current.disallow if field == 'disallow' else current.allow
            if len(target) < MAX_RULES_PER_GROUP:
                target.append(value)

        elif field == 'crawl-delay':
            if current is None:
                current = RobotsGroup(user_agents=['*'])
                groups.append(current)
            accepting_agents = False
            current.crawl_delay = _parse_float(value)

        elif field == 'sitemap':
            # Sitemap is global, not scoped to a group.
            if value and len(report.sitemaps) < MAX_SITEMAPS:
                report.sitemaps.append(value)

        else:
            if field not in report.unknown_directives and len(report.unknown_directives) < MAX_UNKNOWN:
                report.unknown_directives.append(field)

    report.groups = groups

    seen: set[str] = set()
    for group in groups:
        is_wildcard = '*' in group.user_agents
        if is_wildcard and group.crawl_delay is not None and report.wildcard_crawl_delay is None:
            report.wildcard_crawl_delay = group.crawl_delay
        for path in group.disallow:
            report.total_disallow_count += 1
            if is_wildcard and path == '/':
                report.disallows_everything = True
            if path in seen:
                continue
            seen.add(path)
            if _is_sensitive(path) and len(report.sensitive_paths) < MAX_SENSITIVE:
                report.sensitive_paths.append(path)

    return report


def absent(reason: str, status: Optional[int] = None) -> RobotsReport:
    """Report for a site with no usable robots.txt."""
    return RobotsReport(present=False, fetch_reason=reason, fetch_status=status)
