"""Log pull engine for the traffic reduction analysis feature.

Fetches access-log rows for an application over a time range, working
around the API's 10,000-offset pagination cap by bisecting time windows.

Modules:
    windows      — window planning and the bisect drain (pure, no I/O)
    source       — WaasClient adapter with retry/backoff
    preflight    — exact pre-flight count, time/disk projection per mode
    store        — gzipped JSONL on disk, per-day checkpoints, reaping
    analysis     — streaming cache analysis over a completed pull
    crawlers     — crawler classification and published-IP-range verification
    header_audit — live three-probe conditional replay against the origin
    robots       — robots.txt proposal engine, measured by replay
    report       — customer-facing assembly over the above, split by who acts

See docs/TRAFFIC_ANALYSIS_PLAN.md for the design and its constraints.
"""
from app.logpull.analysis import CacheAggregator, analyze_pull
from app.logpull.crawlers import CrawlerAggregator, classify_ua, load_ranges
from app.logpull.preflight import estimate, format_duration, preflight
from app.logpull.report import SECTIONS
from app.logpull.report import build as build_report
from app.logpull.robots import (
    Replay,
    Robots,
    RobotsAggregator,
    propose,
    render_file,
)
from app.logpull.robots import build_report as build_robots_report
from app.logpull.source import LogSource
from app.logpull.store import PullStore, corpus_bytes, corpus_root
from app.logpull.windows import (
    ACCESS_ONLY,
    MODE_FULL,
    MODE_SAMPLE,
    Cancelled,
    DrainStats,
    Window,
    drain,
    plan_days,
    scale_factor,
)

__all__ = [
    'ACCESS_ONLY',
    'CacheAggregator',
    'Cancelled',
    'CrawlerAggregator',
    'DrainStats',
    'Replay',
    'Robots',
    'RobotsAggregator',
    'analyze_pull',
    'build_robots_report',
    'classify_ua',
    'load_ranges',
    'LogSource',
    'MODE_FULL',
    'MODE_SAMPLE',
    'PullStore',
    'SECTIONS',
    'Window',
    'build_report',
    'corpus_bytes',
    'corpus_root',
    'drain',
    'estimate',
    'format_duration',
    'plan_days',
    'preflight',
    'propose',
    'render_file',
    'scale_factor',
]
