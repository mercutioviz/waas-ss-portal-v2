"""Hand-rolled MIT-licensed tech-stack fingerprints.

Everything here is written from public signals — headers a server publishes,
well-known cookie names, obvious HTML markers, and script-src URLs the CDNs
of major products serve from. No external DB is imported. Add entries as
we encounter tech in real customer profiles.

Structure:
- HEADER_FINGERPRINTS  — (header_name_pat, value_pat, label, category)
- COOKIE_FINGERPRINTS  — (cookie_name_prefix, label, category)
- BODY_FINGERPRINTS    — (regex_on_html, label, category)
- SCRIPT_SRC_FINGERPRINTS — (substring_in_url, label, category)
- CDN_RANGES           — CIDR → CDN name (kept; used by the CDN IP-range step)
"""

import ipaddress
import re
from typing import Iterable

from app.profiler.schemas import TechDetection

# ── HEADER FINGERPRINTS ────────────────────────────────────────────────
# (header_name_regex, value_regex, label, category)
HEADER_FINGERPRINTS: list[tuple[str, str, str, str]] = [
    # Web servers
    ('server', r'(?i)nginx', 'nginx', 'Web server'),
    ('server', r'(?i)apache', 'Apache', 'Web server'),
    ('server', r'(?i)microsoft-iis', 'IIS', 'Web server'),
    ('server', r'(?i)litespeed', 'LiteSpeed', 'Web server'),
    ('server', r'(?i)caddy', 'Caddy', 'Web server'),
    ('server', r'(?i)openresty', 'OpenResty', 'Web server'),
    ('server', r'(?i)envoy', 'Envoy', 'Web server'),
    ('server', r'(?i)kestrel', 'Kestrel', 'Web server'),
    ('server', r'(?i)traefik', 'Traefik', 'Reverse proxy'),
    ('server', r'(?i)gunicorn', 'Gunicorn', 'Web server'),
    ('server', r'(?i)cloudflare', 'Cloudflare', 'CDN / WAF'),
    ('server', r'(?i)awselb', 'AWS ELB', 'Load balancer'),
    ('server', r'(?i)AmazonS3', 'Amazon S3', 'Hosting'),
    ('server', r'(?i)Vercel', 'Vercel', 'Hosting'),
    ('server', r'(?i)Netlify', 'Netlify', 'Hosting'),
    ('server', r'(?i)GitHub\.com', 'GitHub Pages', 'Hosting'),

    # Backend runtimes
    ('x-powered-by', r'(?i)php', 'PHP', 'Programming language'),
    ('x-powered-by', r'(?i)express', 'Express', 'Web framework'),
    ('x-powered-by', r'(?i)asp\.net', 'ASP.NET', 'Web framework'),
    ('x-powered-by', r'(?i)next\.js', 'Next.js', 'JS framework'),
    ('x-powered-by', r'(?i)nuxt', 'Nuxt', 'JS framework'),
    ('x-aspnet-version', r'.+', 'ASP.NET', 'Web framework'),
    ('x-aspnetmvc-version', r'.+', 'ASP.NET MVC', 'Web framework'),
    ('x-runtime', r'.+', 'Ruby on Rails / Rack', 'Web framework'),
    ('x-drupal-cache', r'.+', 'Drupal', 'CMS'),
    ('x-drupal-dynamic-cache', r'.+', 'Drupal', 'CMS'),
    ('x-generator', r'(?i)wordpress', 'WordPress', 'CMS'),
    ('x-generator', r'(?i)drupal', 'Drupal', 'CMS'),
    ('x-generator', r'(?i)joomla', 'Joomla', 'CMS'),
    ('x-pingback', r'/xmlrpc\.php', 'WordPress', 'CMS'),
    ('x-shopify-stage', r'.+', 'Shopify', 'Ecommerce'),
    ('x-shopid', r'.+', 'Shopify', 'Ecommerce'),
    ('x-litespeed-cache', r'.+', 'LiteSpeed Cache', 'Caching'),

    # CDN / WAF / edge
    ('via', r'(?i)cloudfront', 'CloudFront', 'CDN'),
    ('via', r'(?i)varnish', 'Varnish', 'Caching'),
    ('via', r'(?i)squid', 'Squid', 'Caching'),
    ('x-served-by', r'(?i)cache-.*', 'Fastly', 'CDN'),
    ('x-fastly-request-id', r'.+', 'Fastly', 'CDN'),
    ('x-cache', r'(?i)akamai', 'Akamai', 'CDN'),
    ('x-akamai-request-id', r'.+', 'Akamai', 'CDN'),
    ('x-akamai-transformed', r'.+', 'Akamai', 'CDN'),
    ('cf-ray', r'.+', 'Cloudflare', 'CDN / WAF'),
    ('cf-cache-status', r'.+', 'Cloudflare', 'CDN / WAF'),
    ('x-amz-cf-id', r'.+', 'CloudFront', 'CDN'),
    ('x-vercel-id', r'.+', 'Vercel', 'Hosting'),
    ('x-nf-request-id', r'.+', 'Netlify', 'Hosting'),
    ('x-bunny-cachestatus', r'.+', 'Bunny CDN', 'CDN'),
    ('x-iinfo', r'.+', 'Imperva', 'CDN / WAF'),
    ('x-sucuri-id', r'.+', 'Sucuri', 'CDN / WAF'),
    ('x-cache-hits', r'.+', 'Varnish', 'Caching'),
]

# ── COOKIE FINGERPRINTS ───────────────────────────────────────────────
# (cookie_name_prefix, label, category)
COOKIE_FINGERPRINTS: list[tuple[str, str, str]] = [
    ('PHPSESSID', 'PHP', 'Programming language'),
    ('JSESSIONID', 'Java Servlet', 'Web framework'),
    ('ASP.NET_SessionId', 'ASP.NET', 'Web framework'),
    ('ARRAffinity', 'Azure App Service', 'Hosting'),
    ('__RequestVerificationToken', 'ASP.NET MVC', 'Web framework'),
    ('connect.sid', 'Express', 'Web framework'),
    ('_session_id', 'Ruby on Rails', 'Web framework'),
    ('_gh_sess', 'GitHub / Rails', 'Web framework'),
    ('_rails_session', 'Ruby on Rails', 'Web framework'),
    ('laravel_session', 'Laravel', 'Web framework'),
    ('XSRF-TOKEN', 'Laravel / Django', 'Web framework'),
    ('csrftoken', 'Django', 'Web framework'),
    ('sessionid', 'Django', 'Web framework'),
    ('wordpress_logged_in_', 'WordPress', 'CMS'),
    ('wp-settings-', 'WordPress', 'CMS'),
    ('wordpress_test_cookie', 'WordPress', 'CMS'),
    ('SESS', 'Drupal', 'CMS'),
    ('__cfduid', 'Cloudflare', 'CDN / WAF'),
    ('__cf_bm', 'Cloudflare', 'CDN / WAF'),
    ('cf_clearance', 'Cloudflare', 'CDN / WAF'),
    ('AWSALB', 'AWS ELB', 'Load balancer'),
    ('AWSELB', 'AWS ELB', 'Load balancer'),
    ('AWSALBCORS', 'AWS ELB', 'Load balancer'),
    ('_shopify_', 'Shopify', 'Ecommerce'),
    ('_secure_session_id', 'Shopify', 'Ecommerce'),
    ('cart', 'Shopify', 'Ecommerce'),
    ('_ga', 'Google Analytics', 'Analytics'),
    ('_gid', 'Google Analytics', 'Analytics'),
    ('_gcl_au', 'Google Ads', 'Advertising'),
    ('_fbp', 'Meta Pixel', 'Advertising'),
    ('_hjSession', 'Hotjar', 'Analytics'),
    ('_hjIncludedInSessionSample', 'Hotjar', 'Analytics'),
    ('mp_', 'Mixpanel', 'Analytics'),
    ('ajs_anonymous_id', 'Segment', 'Analytics'),
    ('intercom-', 'Intercom', 'Live chat'),
    ('__zlcmid', 'Zendesk Chat', 'Live chat'),
    ('drift_', 'Drift', 'Live chat'),
    ('OptanonConsent', 'OneTrust', 'Cookie compliance'),
    ('CookieConsent', 'Cookiebot', 'Cookie compliance'),
]

# ── BODY (HTML) FINGERPRINTS ─────────────────────────────────────────
# (regex, label, category)
BODY_FINGERPRINTS: list[tuple[str, str, str]] = [
    (r'wp-content/', 'WordPress', 'CMS'),
    (r'wp-includes/', 'WordPress', 'CMS'),
    (r'/sites/default/files/', 'Drupal', 'CMS'),
    (r'Drupal\.settings', 'Drupal', 'CMS'),
    (r'/media/jui/', 'Joomla', 'CMS'),
    (r'/skin/frontend/', 'Magento', 'Ecommerce'),
    (r'Shopify\.theme', 'Shopify', 'Ecommerce'),
    (r'cdn\.shopify\.com', 'Shopify', 'Ecommerce'),
    (r'__NEXT_DATA__', 'Next.js', 'JS framework'),
    (r'/_nuxt/', 'Nuxt', 'JS framework'),
    (r'ng-version=', 'Angular', 'JS framework'),
    (r'data-reactroot', 'React', 'JS framework'),
    (r'window\.React', 'React', 'JS framework'),
    (r'window\.Vue', 'Vue.js', 'JS framework'),
    (r'data-vue-meta', 'Vue.js', 'JS framework'),
    (r'window\.SvelteComponent', 'Svelte', 'JS framework'),
    (r'ember-application', 'Ember.js', 'JS framework'),
    (r'x-data=', 'Alpine.js', 'JS framework'),
    (r'gatsby-focus-wrapper', 'Gatsby', 'Static site generator'),
    (r'ghost-search', 'Ghost', 'CMS'),
    (r'generator" content="Hugo', 'Hugo', 'Static site generator'),
    (r'generator" content="Jekyll', 'Jekyll', 'Static site generator'),
    (r'generator" content="Eleventy', 'Eleventy', 'Static site generator'),
    (r'squarespace\.com', 'Squarespace', 'CMS'),
    (r'wixstatic\.com', 'Wix', 'CMS'),
    (r'/wp-json/', 'WordPress', 'CMS'),
    (r'contentful\.com', 'Contentful', 'CMS'),
    (r'sanity\.io', 'Sanity', 'CMS'),
    (r'window\.dataLayer', 'Google Tag Manager', 'Tag manager'),
    (r'ga\(''create''', 'Google Analytics', 'Analytics'),
    (r'fbq\(''init''', 'Meta Pixel', 'Advertising'),
    (r'onetrust-', 'OneTrust', 'Cookie compliance'),
    (r'cookiebot', 'Cookiebot', 'Cookie compliance'),
    (r'analytics\.js', 'Segment', 'Analytics'),
]

# ── SCRIPT SRC FINGERPRINTS ──────────────────────────────────────────
# Substring matches against subresource URLs — this is where modern sites
# reveal most of their stack (analytics, tag managers, ad networks, chat
# widgets, font providers). (substring, label, category)
SCRIPT_SRC_FINGERPRINTS: list[tuple[str, str, str]] = [
    # Analytics
    ('google-analytics.com/analytics.js', 'Google Analytics', 'Analytics'),
    ('googletagmanager.com/gtag/js', 'Google Analytics 4', 'Analytics'),
    ('googletagmanager.com/gtm.js', 'Google Tag Manager', 'Tag manager'),
    ('googletagservices.com', 'Google Ad Manager', 'Advertising'),
    ('doubleclick.net', 'Google DoubleClick', 'Advertising'),
    ('static.hotjar.com', 'Hotjar', 'Analytics'),
    ('script.hotjar.com', 'Hotjar', 'Analytics'),
    ('cdn.mxpnl.com', 'Mixpanel', 'Analytics'),
    ('cdn.segment.com', 'Segment', 'Analytics'),
    ('cdn.amplitude.com', 'Amplitude', 'Analytics'),
    ('matomo.js', 'Matomo', 'Analytics'),
    ('plausible.io/js', 'Plausible', 'Analytics'),
    ('cdn.usefathom.com', 'Fathom', 'Analytics'),
    ('cdn.heapanalytics.com', 'Heap', 'Analytics'),
    ('fullstory.com/s/fs.js', 'FullStory', 'Analytics'),
    ('clarity.ms', 'Microsoft Clarity', 'Analytics'),
    ('adobetm.com', 'Adobe DTM', 'Tag manager'),
    ('assets.adobedtm.com', 'Adobe DTM', 'Tag manager'),
    ('omtrdc.net', 'Adobe Analytics', 'Analytics'),
    ('tealiumiq.com', 'Tealium', 'Tag manager'),
    # Advertising
    ('connect.facebook.net', 'Meta Pixel', 'Advertising'),
    ('snap.licdn.com', 'LinkedIn Insight', 'Advertising'),
    ('analytics.tiktok.com', 'TikTok Pixel', 'Advertising'),
    ('static.ads-twitter.com', 'Twitter Pixel', 'Advertising'),
    ('cdn.taboola.com', 'Taboola', 'Advertising'),
    ('static.criteo.net', 'Criteo', 'Advertising'),
    ('adroll.com', 'AdRoll', 'Advertising'),
    ('bat.bing.com', 'Bing Ads', 'Advertising'),
    # Live chat
    ('widget.intercom.io', 'Intercom', 'Live chat'),
    ('js.intercomcdn.com', 'Intercom', 'Live chat'),
    ('js.driftt.com', 'Drift', 'Live chat'),
    ('js-na1.hs-scripts.com', 'HubSpot', 'CRM'),
    ('static.zdassets.com', 'Zendesk', 'Live chat'),
    ('embed.tawk.to', 'Tawk.to', 'Live chat'),
    ('client.crisp.chat', 'Crisp', 'Live chat'),
    ('cdn.livechatinc.com', 'LiveChat', 'Live chat'),
    # Payment
    ('js.stripe.com', 'Stripe', 'Payment processor'),
    ('paypal.com/sdk/js', 'PayPal', 'Payment processor'),
    ('js.braintreegateway.com', 'Braintree', 'Payment processor'),
    ('checkout.square.js', 'Square', 'Payment processor'),
    # Cookie compliance
    ('cdn.cookielaw.org', 'OneTrust', 'Cookie compliance'),
    ('consent.cookiebot.com', 'Cookiebot', 'Cookie compliance'),
    ('trustarc.com', 'TrustArc', 'Cookie compliance'),
    # Auth
    ('cdn.auth0.com', 'Auth0', 'Authentication'),
    ('okta.com', 'Okta', 'Authentication'),
    # Fonts
    ('fonts.googleapis.com', 'Google Fonts', 'Font service'),
    ('use.typekit.net', 'Adobe Fonts', 'Font service'),
    ('use.fontawesome.com', 'Font Awesome', 'Font service'),
    # CDNs (as script hosts, distinct from IP-range CDN detection)
    ('cdn.jsdelivr.net', 'jsDelivr', 'CDN'),
    ('unpkg.com', 'unpkg', 'CDN'),
    ('cdnjs.cloudflare.com', 'cdnjs', 'CDN'),
    ('code.jquery.com', 'jQuery CDN', 'CDN'),
    # Media
    ('www.youtube.com/iframe_api', 'YouTube', 'Video'),
    ('player.vimeo.com', 'Vimeo', 'Video'),
    ('fast.wistia.com', 'Wistia', 'Video'),
    # JS libraries hint
    ('jquery', 'jQuery', 'JS library'),
    ('lodash', 'Lodash', 'JS library'),
    ('moment.js', 'Moment.js', 'JS library'),
    ('react.production.min.js', 'React', 'JS framework'),
    ('vue.runtime.min.js', 'Vue.js', 'JS framework'),
]

# ── CDN IP-RANGE TABLE (unchanged from phase 2) ──────────────────────
CDN_RANGES: list[tuple[str, str]] = [
    # Cloudflare
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
    # CloudFront
    ('54.192.0.0/16', 'CloudFront'),
    ('54.230.0.0/16', 'CloudFront'),
    ('99.84.0.0/16', 'CloudFront'),
    # Akamai
    ('23.32.0.0/11', 'Akamai'),
    ('23.192.0.0/11', 'Akamai'),
    ('184.24.0.0/13', 'Akamai'),
]

_CDN_NETWORKS = [(ipaddress.ip_network(cidr), name) for cidr, name in CDN_RANGES]


def identify_tech(
    headers: dict,
    cookies: dict,
    body: str,
    subresource_urls: Iterable[str] = (),
) -> list[TechDetection]:
    """Match the collected signals against the fingerprint tables.

    Returns `TechDetection` instances in first-seen order, de-duplicated by
    (name, source). One tech spotted from multiple sources will appear
    multiple times with distinct sources — the results-page renderer can
    collapse them but the provenance is useful for debugging.
    """
    found: list[TechDetection] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, category: str, source: str) -> None:
        key = (name, source)
        if key in seen:
            return
        seen.add(key)
        found.append(TechDetection(name=name, category=category, source=source))

    lower_headers = {k.lower(): (v or '') for k, v in (headers or {}).items()}
    for header_pat, value_pat, label, category in HEADER_FINGERPRINTS:
        header_re = re.compile(header_pat)
        val_re = re.compile(value_pat)
        for hname, hval in lower_headers.items():
            if header_re.fullmatch(hname) and val_re.search(hval):
                _add(label, category, 'header')
                break

    for cookie_prefix, label, category in COOKIE_FINGERPRINTS:
        for real_name in (cookies or {}).keys():
            if real_name.startswith(cookie_prefix):
                _add(label, category, 'cookie')
                break

    if body:
        for pat, label, category in BODY_FINGERPRINTS:
            if re.search(pat, body):
                _add(label, category, 'body')

    for url in subresource_urls:
        if not url:
            continue
        url_lc = url.lower()
        for needle, label, category in SCRIPT_SRC_FINGERPRINTS:
            if needle in url_lc:
                _add(label, category, 'subresource')

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
