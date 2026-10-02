"""Log pull engine for the traffic reduction analysis feature.

Fetches access-log rows for an application over a time range, working
around the API's 10,000-offset pagination cap by bisecting time windows.

Modules:
    windows      — window planning and the bisect drain (pure, no I/O)
    source       — WaasClient adapter with retry/backoff
    preflight    — exact pre-flight count, time/disk projection per mode
    store        — gzipped JSONL on disk, per-day checkpoints, reaping
    analysis     — streaming cache analysis over a completed pull
    header_audit — live three-probe conditional replay against the origin

See docs/TRAFFIC_ANALYSIS_PLAN.md for the design and its constraints.
"""
from app.logpull.analysis import CacheAggregator, analyze_pull
from app.logpull.preflight import estimate, format_duration, preflight
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
    'DrainStats',
    'analyze_pull',
    'LogSource',
    'MODE_FULL',
    'MODE_SAMPLE',
    'PullStore',
    'Window',
    'corpus_bytes',
    'corpus_root',
    'drain',
    'estimate',
    'format_duration',
    'plan_days',
    'preflight',
    'scale_factor',
]
