"""Web App Profiler — probes a customer URL and produces a starter WaaS
config suggestion.

Structured as a subpackage (rather than the repo's usual flat `app/foo.py`)
because probe/fingerprints/recommender share dataclasses and are only
meaningful together.

Entry points for the rest of the app:
    from app.profiler.probe import run_probe
    from app.profiler.recommender import recommend
"""
