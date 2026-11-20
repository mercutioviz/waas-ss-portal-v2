# nginx site for the WaaS Self-Service Portal v2.
#
# Source of truth for /etc/nginx/sites-available/v2.ssportal.waaslab.com,
# which is symlinked from sites-enabled. Edit here, then install:
#
#   sudo cp deploy/nginx/v2.ssportal.waaslab.com \
#           /etc/nginx/sites-available/v2.ssportal.waaslab.com
#   sudo nginx -t && sudo systemctl reload nginx
#
# Since the 2026-11-20 cutover this block serves ALL portal hostnames and is
# the default server. v1 is decommissioned; see docs/CUTOVER.md.

server {
    # v2's own name, plus the names v1 used to answer for. The WaaS edge
    # rewrites the Host header to `portal.waaslab.com` for the old-hostname
    # application, so that name must be listed explicitly — it is what
    # actually arrives on the wire, not `ssportal.waaslab.com`.
    server_name v2.ssportal.waaslab.com
                ssportal.waaslab.com
                portal.waaslab.com
                _;

    # default_server moved here from the v1 site at cutover. Exactly one block
    # may hold it per listen address; nginx -t refuses duplicates.
    listen 80 default_server;
    listen 443 ssl default_server;

    # Covers v2.ssportal.waaslab.com only. Edge traffic arrives over plain
    # HTTP on :80 (access logs show ssl_sni=-), so this cert is consulted only
    # for direct-to-origin HTTPS, where it is already a click-through
    # self-signed cert. A replacement with SANs for all three names is staged
    # at /home/admin/staged-certs/waas-portal-multi.{crt,key} — install it and
    # repoint the two lines below to remove the name mismatch.
    ssl_certificate /etc/ssl/self-signed/v2.ssportal.waaslab.com.crt;
    ssl_certificate_key /etc/ssl/self-signed/v2.ssportal.waaslab.com.key;

    # Socket.IO WebSocket proxy
    location /socket.io/ {
        proxy_pass http://unix:/home/admin/waas-ss-portal-v2/waas-portal-v2.sock;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }

    # Static analysis reports — browsable directory listing
    location /log-reports/ {
        alias /home/admin/waas-log-reports/;
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
        charset utf-8;
    }

    # Flask application
    location / {
        proxy_pass http://unix:/home/admin/waas-ss-portal-v2/waas-portal-v2.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Without these, nginx's 60s default applied and gunicorn's 120s
        # timeout could never fire: slow endpoints (dashboard charts, log
        # pulls, profiler runs) returned a 504 HTML page that broke callers
        # expecting JSON. Set above 120s so gunicorn times out first and the
        # app's own error handling produces the response.
        proxy_connect_timeout 10s;
        proxy_send_timeout 180s;
        proxy_read_timeout 180s;
    }

    # noVNC WebSocket proxy — dynamic port routing for /vnc/<port>/
    location ~ ^/vnc/(\d+)/(.*) {
        proxy_pass http://127.0.0.1:$1/$2$is_args$args;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }
}
