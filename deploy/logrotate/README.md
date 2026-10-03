# logrotate candidate for waas-portal-v2

Review `waas-portal-v2` in this directory, then follow the steps below. Nothing
here touches `/etc` until you run it.

## Two blockers to clear first

**1. logrotate is not installed on this host.**

```
$ logrotate --version
command not found
$ dpkg -l logrotate
no packages found matching logrotate
```

`/etc/logrotate.d/` exists (left behind by another package) but there is no
binary, no `/etc/logrotate.conf`, and no `logrotate.timer`. Dropping a file
into `/etc/logrotate.d/` today would do nothing at all. Installing the package
supplies all three, including the daily timer that actually runs it.

**2. `logs/` is group-writable, which logrotate refuses to rotate.**

```
drwxrwxr-x admin:admin  /home/admin/waas-ss-portal-v2/logs
```

logrotate skips any log whose parent directory is writable by a group other
than root — it reports `insecure permissions` and moves on, silently doing
nothing. Dropping the group write bit is the cleanest fix, and costs nothing:
the directory stays owned by `admin`, so gunicorn still writes and creates
files in it exactly as before.

```bash
chmod g-w /home/admin/waas-ss-portal-v2/logs
```

The alternative is adding `su admin admin` to each stanza, but that one does
not work here — it would drop logrotate to `admin`, which cannot truncate the
root-owned `gunicorn-stderr.log`. Prefer the `chmod`.

## Install

```bash
sudo apt install logrotate
sudo chmod g-w /home/admin/waas-ss-portal-v2/logs
sudo install -o root -g root -m 0644 \
    /home/admin/waas-ss-portal-v2/deploy/logrotate/waas-portal-v2 \
    /etc/logrotate.d/waas-portal-v2
```

## Verify before trusting it

```bash
# Parse the config and show what it would do. Changes nothing.
sudo logrotate -d /etc/logrotate.d/waas-portal-v2

# Force one real rotation now, then confirm all four files still grow.
sudo logrotate -vf /etc/logrotate.d/waas-portal-v2
ls -la /home/admin/waas-ss-portal-v2/logs/
```

The check that matters is the second one. After a forced rotation, make a
request against the portal and confirm **both** `gunicorn-error.log` (rename +
SIGUSR1 path) and `gunicorn-stderr.log` (copytruncate path) are receiving new
lines. If `gunicorn-stderr.log` stays at zero bytes while the service runs,
systemd is still writing to the rotated inode and the stanza is wrong.

## The thing rotation does not fix

`gunicorn-stderr.log` reached **86 MB**. Sampling the last 8 MB of it:

| Share | Source |
|------:|--------|
| 72.0% | `DEBUG:app.waas_client` |
| 26.7% | `INFO:app.waas_client` |
| 1.3%  | everything else |

98.7% of the volume is the WaaS API client, because `app/__init__.py:70-71`
pins that logger to `DEBUG` unconditionally — independent of `FLASK_ENV`:

```python
waas_logger = logging.getLogger('app.waas_client')
waas_logger.setLevel(logging.DEBUG)
```

At `DEBUG` it writes full request headers and the first 500 characters of
every response body. During a traffic-analysis pull that is hundreds of
requests per minute, each carrying real customer log rows — so this file is
both the bulk of the disk usage and a copy of customer traffic data sitting
unrotated on disk.

Rotation bounds the disk. It does not bound that. Dropping the client to
`INFO` in production cuts roughly 72% of the volume; `WARNING` cuts ~98.7%.
That is a separate change to `create_app()`, worth making on its own merits.
