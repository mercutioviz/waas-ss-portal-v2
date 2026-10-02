"""On-disk storage for pulled log rows.

Raw rows go to gzipped JSONL under `instance/`, never into a SQLite column —
a full 30-day pull of a busy app is ~3.8 GB, which is not a database blob.
`instance/` is already v2-local, so this needs no new isolation story.

    instance/log_pulls/<pull_id>/
        day-YYYY-MM-DD.jsonl.gz
        day-YYYY-MM-DD.done.json    checkpoint written only after the day
                                    completes, so a half-written day is
                                    never mistaken for a finished one

The day is the checkpoint unit: a pull interrupted by a service restart
resumes at a day boundary instead of starting over. That same mechanism is
what makes cancel and resume work, so it is not optional on a job that can
run for hours.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import shutil

logger = logging.getLogger(__name__)

DIR_NAME = 'log_pulls'


def corpus_root(instance_path):
    return os.path.join(instance_path, DIR_NAME)


def corpus_bytes(instance_path):
    """Total bytes across every retained pull. 0 if nothing exists yet."""
    root = corpus_root(instance_path)
    if not os.path.isdir(root):
        return 0
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:  # pragma: no cover — file vanished mid-walk
                pass
    return total


class PullStore:
    """Reads and writes one pull's directory."""

    def __init__(self, instance_path, pull_id):
        self.instance_path = instance_path
        self.pull_id = pull_id
        self.root = os.path.join(corpus_root(instance_path), str(pull_id))

    # --- layout -----------------------------------------------------------

    def ensure(self):
        os.makedirs(self.root, exist_ok=True)
        return self.root

    def day_path(self, date):
        return os.path.join(self.root, f'day-{date}.jsonl.gz')

    def done_path(self, date):
        return os.path.join(self.root, f'day-{date}.done.json')

    def meta_path(self):
        return os.path.join(self.root, 'meta.json')

    # --- checkpoints ------------------------------------------------------

    def is_day_done(self, date):
        return os.path.exists(self.done_path(date))

    def read_day_marker(self, date):
        try:
            with open(self.done_path(date), encoding='utf-8') as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def mark_day_done(self, date, marker):
        """Write the day's checkpoint.

        Written last, after the data file is closed and flushed, so the
        marker's presence genuinely implies the day is complete.
        """
        with open(self.done_path(date), 'w', encoding='utf-8') as fh:
            json.dump(marker, fh, indent=1)

    def completed_days(self):
        if not os.path.isdir(self.root):
            return []
        return sorted(
            name[len('day-'):-len('.done.json')]
            for name in os.listdir(self.root)
            if name.startswith('day-') and name.endswith('.done.json')
        )

    def resume_state(self):
        """Rows and days already on disk, for restarting an interrupted pull."""
        rows = 0
        days = self.completed_days()
        for date in days:
            marker = self.read_day_marker(date) or {}
            rows += marker.get('sampled_rows') or 0
        return {'days': days, 'rows': rows}

    def write_meta(self, meta):
        self.ensure()
        with open(self.meta_path(), 'w', encoding='utf-8') as fh:
            json.dump(meta, fh, indent=1)

    def read_meta(self):
        try:
            with open(self.meta_path(), encoding='utf-8') as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    # --- writing ----------------------------------------------------------

    def open_day(self, date):
        """Writer for one day. Truncates any partial file from a prior run —
        the absence of a `.done.json` means whatever is there is incomplete
        and must not be appended to."""
        self.ensure()
        return DayWriter(self.day_path(date))

    # --- reading ----------------------------------------------------------

    def iter_rows(self, dates=None):
        """Stream rows back for analysis, oldest day first.

        A generator on purpose: a full pull does not fit in memory, and the
        analysis layer accumulates counters per chunk rather than holding
        the row set.
        """
        if not os.path.isdir(self.root):
            return
        names = sorted(
            name for name in os.listdir(self.root)
            if name.startswith('day-') and name.endswith('.jsonl.gz')
        )
        for name in names:
            date = name[len('day-'):-len('.jsonl.gz')]
            if dates is not None and date not in dates:
                continue
            with gzip.open(os.path.join(self.root, name), 'rt', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        # A pull killed mid-write can leave one torn final
                        # line. Skip it rather than failing the analysis.
                        logger.warning('logpull: skipping malformed row in %s', name)

    # --- size & removal ---------------------------------------------------

    def size_bytes(self):
        if not os.path.isdir(self.root):
            return 0
        total = 0
        for name in os.listdir(self.root):
            try:
                total += os.path.getsize(os.path.join(self.root, name))
            except OSError:  # pragma: no cover
                pass
        return total

    def delete_raw(self):
        """Remove the bulk rows, keep the directory and its metadata.

        This is the retention sweep's normal action: the GB go, the pull and
        its report stay readable.
        """
        if not os.path.isdir(self.root):
            return 0
        freed = 0
        for name in os.listdir(self.root):
            if not name.endswith('.jsonl.gz'):
                continue
            path = os.path.join(self.root, name)
            try:
                freed += os.path.getsize(path)
                os.remove(path)
            except OSError:  # pragma: no cover
                pass
        return freed

    def delete_all(self):
        if not os.path.isdir(self.root):
            return 0
        freed = self.size_bytes()
        shutil.rmtree(self.root, ignore_errors=True)
        return freed


class DayWriter:
    """Gzip JSONL writer for a single day."""

    def __init__(self, path):
        self.path = path
        self._fh = gzip.open(path, 'wt', encoding='utf-8')
        self.rows = 0

    def write(self, rows):
        for row in rows:
            self._fh.write(json.dumps(row, separators=(',', ':')))
            self._fh.write('\n')
        self.rows += len(rows)

    def flush(self):
        self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def size_bytes(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
