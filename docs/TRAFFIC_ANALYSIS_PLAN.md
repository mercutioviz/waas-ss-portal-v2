# Traffic Reduction Analysis — Development Plan

Productizes the one-off engagement in `/home/admin/waas-log-reports/icc-swarm-30d/`
(ICC `*.iccsafe.org SWARM`, 30 days, 61.4M requests) as a portal feature.

The profiler answers *"what does this site's configuration say?"* This feature
answers *"what is the traffic actually doing, and what would change if we fixed
it?"* Several ICC findings contradicted what the config implied, so this is a
sibling of the profiler, not an extension of it.

---

## 0. Status

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Land `traffic_insights.py` + truncation-aware config advisor | **done** (`64f34e5`, `bc1167f`) |
| 1 | Log pull engine: bisect fetcher, pre-flight, storage, retention, progress | **done** |
| 2 | Admin storage utilities page | **done** (landed with phase 1) |
| 3 | Cache analysis over a pull (revalidation ratio, repeat-fetch) + live header audit | **done** |
| 4 | Crawler analysis (classification, IP verification, URL-space cross-tab) | **done** |
| 5 | robots.txt proposal engine with measured before/after | **done** |
| 6 | Customer-facing report + downloadable artifacts | planned |

Phases 3 and 4 are independent and each useful alone.

---

## 1. The two constraints that shape everything

### 1.1 Wall-clock, not disk

Measured on the ICC run: **457 rows/s** sustained end-to-end (including bisect
and count queries), **61 bytes/row** gzipped on disk.

| App / window | Mode | Rows | Time | Disk |
|---|---|---|---|---|
| ICC 30d | full | 61,394,605 | **37.3 h** | 3.76 GB |
| ICC 30d | sample 4% | 2,468,063 | 1.5 h | 0.15 GB |
| ICC 7d | full | 14,325,408 | **8.7 h** | 0.88 GB |
| ICC 7d | sample 4% | 575,881 | 0.3 h | 0.04 GB |

With 96 GB free, disk never binds first — time does. So **mode is not a blind
checkbox**. A single count query (~0.3 s, exact) runs before the user commits
and turns the choice into an informed one: estimated rows, time, bytes, and a
recommended mode. On a small app, full is minutes and should be the default; on
ICC 30d, full must carry an explicit warning.

### 1.2 One gevent worker

`gunicorn.conf.py`: `workers = 1`, `worker_class = GeventWebSocketWorker`
(single worker is required for Flask-SocketIO without Redis).

Gevent yields on network I/O, so the fetch loop coexists fine with request
serving. **JSON parsing of millions of rows does not** — it is CPU-bound and
will block the event loop, freezing the portal for every other user for the
duration.

Mitigations, in the order they matter:

1. **Never parse during collection.** The fetcher writes raw response text
   straight to gzip. Parsing happens in the analysis phase, over a bounded
   stream, in chunks.
2. **Explicit `gevent.sleep(0)`** between pages and every N parsed rows, so the
   hub gets a turn even inside CPU-ish stretches.
3. **Analysis is streaming and incremental** — accumulate counters per chunk,
   never hold the full row set in memory.

If the portal still stutters under load, the escape hatch is a separate worker
process (Redis message queue for SocketIO), but that is a larger change and is
deliberately out of scope for phase 1.

### 1.3 Restart survival

`systemctl restart waas-portal-v2` kills a multi-hour job. The job must
therefore be **resumable**: each completed window is checkpointed, and a pull
left in `RUNNING` at startup is either resumed or marked `INTERRUPTED` with its
partial data intact and flagged partial. (The one-off `collect.py` used per-day
`.done.json` markers for exactly this reason.)

---

## 2. The log pull engine

New package `app/logpull/`.

### 2.1 The 10k cap and bisect logic

The logs API refuses pagination past **offset 10,000**. Any window holding more
than that cannot be drained by paging alone — it must be split in time until
each sub-window fits.

```
drain(window):
    n = count(window)                  # cheap: items_per_page=1, read `count`
    if n == 0:            return
    if n <= SAFE (9000):  page through it, write rows, checkpoint
    else:                 split window in half; drain each
```

Two details the one-off script got right and the module must keep:

- **`SAFE = 9000`, not 10,000.** Live traffic arrives *during* the pull; a
  window that counted 9,998 can overflow before it is drained.
- **A floor on window width.** A burst can exceed 9,000 rows inside one second,
  which no split can fix. At the floor, drain what is reachable, mark the
  window `truncated`, and propagate that flag to the report. Silent truncation
  is the failure mode that makes a report wrong rather than incomplete.

### 2.2 One engine, two modes

The bisect drainer is mode-agnostic. Mode only decides *which windows* get
drained:

| Mode | Window plan |
|---|---|
| `FULL` | Contiguous windows covering the entire range |
| `SAMPLE` | `WIN`-second slices every `SLOT` seconds (ICC used 300s every 7200s) |

Sampling must record its **measured** scale factor, not the nominal one. On
ICC the nominal rate was 4.17% but the measured factor was **24.87×**, not 24 —
sampling on even UTC-hour boundaries biases the draw. The scale factor is
derived per-day from `day_total / sampled_rows` and stored with the pull; every
extrapolated figure in the report uses it. Validated to 1.3% against an
independent exact count on ICC.

### 2.3 Exact-count layer

Independently of any pull, count queries are exact and cost ~0.3 s. Anything
filterable should be *counted*, not estimated from a sample. This layer must
encode the filter semantics as API, not as documentation — the trap cost a
rewrite during the ICC engagement:

- Clauses on the **same field OR** together. Clauses on **different fields AND**.
  There is no same-field AND. (`counts2.py` computed "calendar AND /list/" and
  got a subset *larger* than its container — 1,895,428 vs 1,870,836. That is
  how the bug announced itself.)
- Only `is` and `contains` are real conditions; anything else silently degrades
  to `is`.
- `contains` is case-sensitive.
- `CacheHit` is not filterable server-side.

A `count_matching(field, value)` helper that refuses to build an impossible
same-field conjunction is the right shape — it makes the trap unrepresentable.

### 2.4 Storage layout

Raw rows go to **disk, not SQLite**. A 3.8 GB JSON blob in a DB column is not a
thing we are going to do.

```
instance/log_pulls/<pull_id>/
    meta.json              # plan, mode, scale factors, truncation flags
    day-YYYY-MM-DD.jsonl.gz
    day-YYYY-MM-DD.done.json   # checkpoint: window list drained, row counts
```

`instance/` is already v2-local and excluded from v1 (per CLAUDE.md isolation
rules), so this needs no new isolation story.

---

## 3. Storage & retention

**Decision: reap the bulk, keep the conclusions.** The raw corpus is large and
has a short useful life; the aggregates and the customer-facing report are tiny
and should outlive it. Splitting the two retention windows is what makes an
aggressive raw retention safe.

| Artifact | Size | Retention | Constant |
|---|---|---|---|
| Raw `.jsonl.gz` rows | GB | **3 days** | `LOG_PULL_RAW_RETENTION_DAYS = 3` |
| Aggregates + findings (DB JSON) | KB | 30 days | `LOG_PULL_RESULT_RETENTION_DAYS = 30` |
| Generated report + robots.txt | KB | 30 days | (same) |

After raw reaping the pull stays visible and its report still opens; it is
marked *raw data expired*, and re-running a deeper cut requires a new pull.

Cleanup hooks into the existing APScheduler cron block in `app/__init__.py`
alongside `cleanup_site_profiles` (3:17) and `cleanup_security_metrics` (3:37).
**Use 3:57** to keep the established spacing.

### 3.1 Disk-space guards

Three layers, because the pre-flight estimate can be wrong:

1. **Pre-flight.** `shutil.disk_usage()` vs the estimate. Require
   `estimated × 1.5` headroom *and* ≥10 GB still free afterwards. Below that,
   warn prominently; far below, refuse and suggest sampling or a shorter window.
2. **Corpus cap.** `LOG_PULL_MAX_TOTAL_GB` — refuse to start a new pull while
   the existing corpus exceeds it, pointing at the admin cleanup page.
3. **Mid-flight.** Re-check free space every N windows. Under a hard floor,
   abort to `ABORTED_DISK`, keep partial data, flag it partial. Aborting with
   usable partial data beats filling the disk and taking the portal down.

The pre-flight estimate is shown to the user *before* they commit, in the same
panel as the time estimate.

---

## 4. Admin utilities page

`/admin/storage`, alongside the existing admin blueprint (`admin_required`).

- Table of all pulls: owner, account/app, window, mode, status, row count,
  **on-disk size**, age, raw-expiry date.
- Per-pull **Delete raw** (frees the GB, keeps the report) and **Delete pull**.
- Bulk **Reap now** — runs the retention sweep on demand.
- Disk summary: corpus total, filesystem free, cap headroom.

Per CLAUDE.md: all destructive actions are **POST** form buttons with
`csrf_token()`, never `<a>` links. Deletions write to `AuditLog` (field is
`timestamp`, not `created_at`).

---

## 5. TODO — system-level logrotate (separate track)

**Independent of this feature; do not bundle into a phase.**

`logs/` is currently **70 MB** and unmanaged: `gunicorn-access.log`,
`gunicorn-error.log`, `gunicorn-stdout.log`, `gunicorn-stderr.log` grow without
bound.

Task: add `/etc/logrotate.d/waas-portal-v2` — daily, `rotate 14`, `compress`,
`delaycompress`, `missingok`, `notifempty`, `copytruncate` (gunicorn holds the
fd; `copytruncate` avoids needing a signal/restart).

Constraints: **v2 paths only.** Must not touch v1's logs or any v1 unit/site
file. Writing to `/etc/` requires explicit confirmation before proceeding.

---

## 6. Progress & status UI

A 9-hour job changes the weighting the profiler uses. There, SocketIO is the
source of truth and the JSON endpoint is a fallback. Here that inverts:

> **The DB row is the source of truth; SocketIO is an optimization.**

A user will close the tab, refresh, reconnect from another machine, and survive
a service restart during a pull this long. Progress that lives only in emitted
events cannot serve any of that.

### 6.1 Durable progress

`LogPull` carries live progress columns — `phase`, `rows_fetched`,
`rows_expected`, `windows_done`, `bytes_on_disk`, `current_window_start`,
`eta_seconds`. Written on a **throttle** (every ~2 s or N windows), never per
page, to avoid write amplification over tens of thousands of pages.

### 6.2 Honest ETA

The single pre-flight count gives the **exact** total row count for the window
before any fetching starts. So progress is `rows_fetched / rows_expected` —
a real fraction, not a guess — and the ETA follows from observed throughput.
This is why the pre-flight count is worth its 0.3 s even in full mode.

(Window *counts* can't serve this: windows are discovered adaptively as the
bisect proceeds, so the denominator wouldn't be known upfront.)

### 6.3 Transport

Reuse the profiler's plumbing, which already solved the hard parts:

- SocketIO room keyed on `session_id`, event `logpull_progress`.
- **`pending_join(session_id)` called synchronously before spawning the
  greenlet** — `app/routes/profiler.py:195` documents the race: the browser's
  `join` can arrive before the greenlet registers the Event and be silently
  dropped.
- `GET /logs/pulls/<id>/status` returning the durable progress columns. Polled
  every ~5 s as fallback, and used as the **primary** source on page load and
  after any reconnect.

### 6.4 What the user sees

Phase label (`counting → planning → fetching → analyzing → report`), a progress
bar with rows done / expected, elapsed + ETA, live on-disk size against the
budget, and a **Cancel** button. Cancellation is cooperative — checked at window
boundaries — and keeps partial data, flagged partial.

---

## 7. Analysis & report

### 7.1 Analysis layers over a completed pull

Existing `app/traffic_insights.py` operates on a single 1000-row page and
measures **edge** `CacheHit`, latency and error rates. It is reused for its
aggregation shape but extended, because the ICC findings needed metrics it does
not compute:

| New metric | Why the existing module can't answer it |
|---|---|
| **Revalidation ratio** `304/(200+304)` per extension | `CacheHit` is *edge* cache; this is *browser* behaviour. ICC: 0.53% on JS. |
| **Repeat-fetch** same `(ClientIP, URL)` within one 5-min bucket | Needs a cross-row, cross-page view. ICC: 2.36M redundant fetches. |
| **Crawler classification + IP verification** | No bot analysis exists anywhere in the repo. |
| **Per-host breakdown** | ICC's wildcard app spans ~15 hosts; `my.iccsafe.org` was 5.5% of requests but **41% of egress**. The finding lived in the breakdown. |

Crawler verification matches against published prefix lists using
`ipaddress` network containment — **never substring matching**. Lists are
fetched and cached locally with an age bound (Google's are under
`developers.google.com/static/crawling/ipranges/*.json`; Applebot publishes at
`search.developer.apple.com/applebot.json`). On ICC this established the crawl
load was genuine (bingbot ~100%, Applebot 99.5%, Googlebot 92.8%), which is what
made "tune crawl directives" the right remedy instead of "block".

### 7.2 Three classes of recommendation

The report must separate these, because they have different owners and the
customer needs to know who acts:

1. **WaaS config** — what the portal can change itself. ICC: CDN caching
   disabled (`CacheHit` 0 on 100% of rows), and the auto-added
   `remove-accept-encoding-header` rewrite at sequence 2 killing origin
   compression. Note that rewrite is load-bearing on all 59 apps, so this is
   advisory with context, not a one-click fix.
2. **Origin / backend** — what only the customer's server team can change.
   ICC: Apache `mod_deflate` appending `-gzip` to ETags. Under RFC 9110 §13.2.2
   a server receiving both validators must honour `If-None-Match` and *ignore*
   `If-Modified-Since` — so a broken ETag doesn't merely fail to help, it
   **suppresses a `Last-Modified` that works perfectly on its own**. Diagnosed
   only by a three-probe conditional replay; a single probe sending both looks
   like "conditional requests unsupported" and hides the cause.
3. **robots.txt** — origin-served, so WaaS cannot deploy it. Advisory + a
   downloadable file.

### 7.3 robots.txt proposal engine

The piece that made the ICC report credible, and the one that turns this from a
report into a product: **generate a candidate file, replay it against the real
sampled traffic, and report measured deltas** — requests and bytes, split by
crawler, with which rule does the work.

Non-negotiables, each learned the hard way:

- **Google-spec matching**: wildcards, `$`, longest-pattern-wins, group merging.
  Patterns are **anchored at path start** — this is precisely why ICC's existing
  `Disallow: /tag` and `/category` blocked ~nothing: the traffic was at
  `/news-and-events-calendar/tag/...` (242,413 + 590,147 requests / 30d).
- **Never ship an unmeasured claim.** The draft asserted the proposal covered
  "80–100%" of five crawlers' fetches. Measured, it was **56.4–86.0%** — and
  measuring surfaced the more valuable fact that only **9.2% of Googlebot** was
  affected.
- **Report the ceiling.** 9.68% of *non-crawler* requests matched the same
  patterns. robots.txt cannot touch those, so it caps out near a third. The
  replay harness computes this by testing non-bot rows against the `*` group.
- **Measure the exact bytes that ship.** A late `tribe_paged` rule invalidated
  the earlier measurement; the file must be re-measured against its own final
  content.

Reference implementations to port, read-only:
`/home/admin/waas-log-reports/banz-7d/robots_spec.py` (`Robots`, `allowed`,
`group_for`) and `icc-swarm-30d/propose_robots.py`.

### 7.4 Deliverables

- In-portal report view.
- **Download robots.txt** — with measured impact in the header comment, as in
  `icc-swarm-30d/www.iccsafe.org.robots.txt.suggested`.
- **Export standalone HTML** — the self-contained format already shipped to
  customers in `/home/admin/waas-log-reports/`.

---

## 8. Open calls

1. **Full mode on very large apps.** 37 h for ICC 30d. Hard-refuse above a
   threshold, or allow with a typed confirmation?
2. **Concurrent pulls.** One worker, one event loop — recommend serializing to
   one active pull at a time, queueing the rest.
3. **Scheduled/recurring pulls.** APScheduler is already present. Worth it, or
   on-demand only for v1?
