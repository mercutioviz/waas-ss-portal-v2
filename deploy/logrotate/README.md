# Log rotation for waas-portal-v2

**Installed and verified on 2026-10-03.** This directory holds the source of
truth for `/etc/logrotate.d/waas-portal-v2`; edit `waas-portal-v2` here and
re-run the install command to push a change.

## What changed on 2026-10-03

Three things landed together, because the rotation design depended on the first
two:

1. **The unit's stdio moved to the journal.** `StandardOutput` and
   `StandardError` in `/etc/systemd/system/waas-portal-v2.service` were
   `append:` paths into `logs/`; they are now `journal`. Read them with
   `journalctl -u waas-portal-v2 -f`.
2. **The WaaS client logger dropped from DEBUG to INFO** in production
   (`app/__init__.py`). See "The thing rotation does not fix" below for why.
3. **logrotate was installed and configured** for the two files gunicorn still
   writes itself.

The old `logs/gunicorn-stdout.log` and `logs/gunicorn-stderr.log` are no longer
written by anything. Whatever is left on disk is historical.

## Why only two files are rotated

`gunicorn-access.log` and `gunicorn-error.log` are opened by gunicorn itself
(`accesslog` / `errorlog` in `gunicorn.conf.py`), running as `admin`, and
gunicorn reopens them on **SIGUSR1**. So they rotate by rename plus a signal —
no truncation window, no lost writes, no `copytruncate`.

The unit's stdout/stderr used to need a second stanza with `copytruncate`,
because systemd opened those files as root and held the descriptors for the
life of the service with no reopen signal. Moving them to the journal removes
that whole problem: journald does its own rotation and vacuuming.

## Install

```bash
sudo apt install logrotate
sudo chmod g-w /home/admin/waas-ss-portal-v2/logs
sudo install -o root -g root -m 0644 \
    /home/admin/waas-ss-portal-v2/deploy/logrotate/waas-portal-v2 \
    /etc/logrotate.d/waas-portal-v2
```

The `chmod` is not optional. logrotate skips any log whose parent directory is
writable by a group other than root — it reports `insecure permissions` and
moves on, silently doing nothing. Dropping the group write bit costs nothing:
the directory stays owned by `admin`, so gunicorn still writes and creates
files in it exactly as before.

(The usual alternative, `su admin admin` in the stanza, was the wrong fix here
when the root-owned stderr file still needed truncating. It is moot now, but
the `chmod` remains the cleaner answer.)

The binary installs to `/usr/sbin/logrotate`, which is not on a non-root
`PATH` — invoke it by full path when running it by hand. `apt` also enables
`logrotate.timer`, which is what actually runs it daily.

## Verify

```bash
# Parse the config and show what it would do. Changes nothing.
sudo /usr/sbin/logrotate -d /etc/logrotate.d/waas-portal-v2

# Force one real rotation now.
sudo /usr/sbin/logrotate -vf /etc/logrotate.d/waas-portal-v2
```

The check that matters is not the file listing — a fresh zero-byte
`gunicorn-error.log` looks identical whether gunicorn reopened it or is still
writing to the rotated inode, because gunicorn only speaks at startup and on
signals. Compare inodes instead:

```bash
for p in $(pgrep -f waas-ss-portal-v2/venv/bin/gunicorn); do
    sudo stat -L -c "$p fd3 -> %i" /proc/$p/fd/3 2>/dev/null
done
stat -c "on-disk  -> %i" /home/admin/waas-ss-portal-v2/logs/gunicorn-error.log
```

Every gunicorn process holding fd 3 must report the same inode as the on-disk
file. If one still points at `gunicorn-error.log-<date>`, the SIGUSR1 never
arrived and the postrotate script is wrong.

Verified on 2026-10-03: arbiter and worker both reopened onto the new inode.

## Known: the access log is never written

`logs/gunicorn-access.log` has been zero bytes since it was created on
2026-08-12, even though `accesslog` is configured and gunicorn holds the file
open. The cause is `worker_class = GeventWebSocketWorker` — it handles the
response path itself and never calls gunicorn's access logger.

This is pre-existing and unrelated to rotation; `notifempty` means logrotate
correctly skips the file. It is listed in the stanza so that rotation is
already in place if the worker class ever changes. Request-level logging today
comes from nginx's own access log, not from gunicorn.

## The thing rotation does not fix

`gunicorn-stderr.log` reached **86 MB**. Sampling the last 8 MB of it:

| Share | Source |
|------:|--------|
| 72.0% | `DEBUG:app.waas_client` |
| 26.7% | `INFO:app.waas_client` |
| 1.3%  | everything else |

98.7% of the volume was the WaaS API client, because `app/__init__.py` pinned
that logger to `DEBUG` unconditionally — independent of `FLASK_ENV`. At `DEBUG`
it writes full request headers and the first 500 characters of every response
body. During a traffic-analysis pull that is hundreds of requests per minute,
each carrying real customer log rows — so the file was both the bulk of the
disk usage and a copy of customer traffic data sitting unrotated on disk.

Rotation bounds the disk. It does not bound that. The logger now follows
`app.debug`, so production runs at `INFO`: the one-line per-call record stays,
the payloads go. Raise it to `DEBUG` only while actively debugging the client,
and lower it again afterwards.

## Journal sizing

`/var/log/journal` exists, so journald storage is persistent and survives
reboots. `journald.conf` sets no `SystemMaxUse` or `MaxRetentionSec`, so the
defaults apply: 10% of the filesystem capped at 4 GB. On a 118 GB root
filesystem that cap is 4 GB, and current usage is ~87 MB.

`ForwardToSyslog=yes` is set but inert — rsyslog is not active and there is no
`/var/log/syslog`, so nothing is duplicated to a second unrotated file. If
rsyslog is ever enabled, revisit this: the unit's output would start landing in
syslog as well.
