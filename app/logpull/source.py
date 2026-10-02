"""Adapter from `WaasClient` to the interface `windows.drain` expects.

Kept separate from the drain engine so the engine can be tested against a
fake, and so retry/backoff policy lives in exactly one place.
"""
from __future__ import annotations

import logging
import time

from app.logpull.windows import ACCESS_ONLY, PAGE_SIZE, Window
from app.waas_client import WaasApiError

logger = logging.getLogger(__name__)

DEFAULT_TRIES = 5
BACKOFF_BASE = 2.0


class LogSource:
    """Counting and paging against one application's logs.

    `count()` is the cheap primitive the whole design leans on: one request
    with `items_per_page=1`, reading only the `count` field. It is exact and
    costs a fraction of a second, which is what makes both the pre-flight
    estimate and the bisect affordable.
    """

    def __init__(self, client, app_name, filter_fields=None, tries=DEFAULT_TRIES, sleep=time.sleep):
        self.client = client
        self.app_name = app_name
        self.filter_fields = ACCESS_ONLY if filter_fields is None else filter_fields
        self.tries = tries
        self._sleep = sleep
        self.requests = 0

    def _call(self, what, **kwargs):
        """One API call with bounded exponential backoff.

        Transient 5xx and timeouts are common over a multi-hour pull; giving
        up on the first one would throw away hours of work.
        """
        last = None
        for attempt in range(self.tries):
            try:
                self.requests += 1
                return self.client.get_logs(
                    self.app_name,
                    filter_fields=self.filter_fields,
                    **kwargs,
                )
            except WaasApiError as exc:
                last = exc
                if attempt == self.tries - 1:
                    break
                delay = BACKOFF_BASE * (attempt + 1)
                logger.warning(
                    'logpull: %s failed (attempt %s/%s): %s — retrying in %ss',
                    what, attempt + 1, self.tries, exc, delay,
                )
                self._sleep(delay)
        raise last

    def count(self, window: Window) -> int:
        """Exact row count for `window`. One request, one integer."""
        result = self._call(
            'count',
            page=1,
            items_per_page=1,
            from_epoch=window.start,
            to_epoch=window.end,
        )
        return result.get('count') or 0

    def page(self, window: Window, page: int) -> list[dict]:
        result = self._call(
            'page',
            page=page,
            items_per_page=PAGE_SIZE,
            from_epoch=window.start,
            to_epoch=window.end,
        )
        return result.get('results') or []
