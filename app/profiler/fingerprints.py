"""Header, cookie, and body regexes for identifying tech stacks; CDN IP
ranges for identifying reverse proxies in front of the origin.

Kept intentionally small — this is a hint layer for the recommender, not a
security scanner. Add entries as we run into real-world sites.
"""

import ipaddress
import re

# (header_name_lowercase, value_regex) → label
HEADER_FINGERPRINTS: list[tuple[tuple[str, str], str]] = [
    (('server', r'(?i)nginx'), 'nginx'),
    (('server', r'(?i)apache'), 'Apache'),
    (('server', r'(?i)microsoft-iis'), 'IIS'),
    (('server', r'(?i)cloudflare'), 'Cloudflare'),
    (('server', r'(?i)litespeed'), 'LiteSpeed'),
    (('server', r'(?i)caddy'), 'Caddy'),
    (('x-powered-by', r'(?i)php'), 'PHP'),
    (('x-powered-by', r'(?i)express'), 'Express (Node.js)'),
    (('x-powered-by', r'(?i)asp\.net'), 'ASP.NET'),
    (('x-powered-by', r'(?i)next\.js'), 'Next.js'),
    (('x-generator', r'(?i)wordpress'), 'WordPress'),
    (('x-generator', r'(?i)drupal'), 'Drupal'),
    (('x-drupal-cache', r'.+'), 'Drupal'),
    (('via', r'(?i)cloudfront'), 'CloudFront'),
    (('via', r'(?i)varnish'), 'Varnish'),
    (('x-served-by', r'(?i)cache-.*'), 'Fastly'),
    (('x-cache', r'(?i)akamai'), 'Akamai'),
    (('x-akamai-.*', r'.+'), 'Akamai'),
]

COOKIE_FINGERPRINTS: list[tuple[str, str]] = [
    ('PHPSESSID', 'PHP'),
    ('JSESSIONID', 'Java (Servlet)'),
    ('ASP.NET_SessionId', 'ASP.NET'),
    ('connect.sid', 'Express (Node.js)'),
    ('__cfduid', 'Cloudflare'),
    ('__cf_bm', 'Cloudflare'),
    ('_gh_sess', 'GitHub / Rails'),
    ('wordpress_logged_in_', 'WordPress'),
    ('wp-settings-', 'WordPress'),
    ('SESS', 'Drupal'),
    ('laravel_session', 'Laravel'),
]

BODY_FINGERPRINTS: list[tuple[str, str]] = [
    (r'wp-content/', 'WordPress'),
    (r'wp-includes/', 'WordPress'),
    (r'/sites/default/files/', 'Drupal'),
    (r'Drupal\.settings', 'Drupal'),
    (r'__NEXT_DATA__', 'Next.js'),
    (r'/_nuxt/', 'Nuxt'),
    (r'ng-version=', 'Angular'),
    (r'data-reactroot', 'React'),
    (r'/media/jui/', 'Joomla'),
    (r'Shopify\.theme', 'Shopify'),
    (r'/skin/frontend/', 'Magento'),
]

# CDN identification by CIDR. Small, well-known ranges only — the intent is
# to flag "your public IP is a CDN edge; you must supply the origin," not to
# be an exhaustive ASN catalogue.
CDN_RANGES: list[tuple[str, str]] = [
    # Cloudflare — a subset of their published v4 ranges
    ('173.245.48.0/20', 'Cloudflare'),
    ('103.21.244.0/22', 'Cloudflare'),
    ('103.22.200.0/22', 'Cloudflare'),
    ('103.31.4.0/22', 'Cloudflare'),
    ('141.101.64.0/18', 'Cloudflare'),
    ('108.162.192.0/18', 'Cloudflare'),
    ('190.93.240.0/20', 'Cloudflare'),
    ('188.114.96.0/20', 'Cloudflare'),
    ('197.234.240.0/22', 'Cloudflare'),
    ('198.41.128.0/17', 'Cloudflare'),
    ('162.158.0.0/15', 'Cloudflare'),
    ('104.16.0.0/13', 'Cloudflare'),
    ('104.24.0.0/14', 'Cloudflare'),
    ('172.64.0.0/13', 'Cloudflare'),
    ('131.0.72.0/22', 'Cloudflare'),
    # Fastly
    ('151.101.0.0/16', 'Fastly'),
    ('199.232.0.0/16', 'Fastly'),
    # CloudFront — one representative range; full list is much larger
    ('54.192.0.0/16', 'CloudFront'),
    ('54.230.0.0/16', 'CloudFront'),
    ('99.84.0.0/16', 'CloudFront'),
    # Akamai — one representative range
    ('23.32.0.0/11', 'Akamai'),
    ('23.192.0.0/11', 'Akamai'),
    ('184.24.0.0/13', 'Akamai'),
]

_CDN_NETWORKS: list[tuple[ipaddress.IPv4Network, str]] = [
    (ipaddress.ip_network(cidr), name) for cidr, name in CDN_RANGES
]


def _matches_header(name_pat: str, value: str, value_pat: str) -> bool:
    return bool(re.search(value_pat, value))


def identify_tech(headers: dict, cookies: dict, body: str) -> list[str]:
    """Return a de-duplicated, ordered list of detected tech labels."""
    found: list[str] = []
    lower_headers = {k.lower(): v for k, v in (headers or {}).items()}
    for (header_pat, value_pat), label in HEADER_FINGERPRINTS:
        for hname, hval in lower_headers.items():
            if re.fullmatch(header_pat, hname) and _matches_header(header_pat, hval, value_pat):
                if label not in found:
                    found.append(label)
                break
    for cookie_name, label in COOKIE_FINGERPRINTS:
        for real_name in (cookies or {}).keys():
            if real_name.startswith(cookie_name):
                if label not in found:
                    found.append(label)
                break
    if body:
        for pat, label in BODY_FINGERPRINTS:
            if re.search(pat, body):
                if label not in found:
                    found.append(label)
    return found


def is_cdn_ip(ip_string: str) -> str | None:
    """Return the CDN name if `ip_string` falls in a known CDN range, else None."""
    try:
        addr = ipaddress.ip_address(ip_string)
    except ValueError:
        return None
    for net, name in _CDN_NETWORKS:
        if addr.version == net.version and addr in net:
            return name
    return None
