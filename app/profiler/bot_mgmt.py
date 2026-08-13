"""Classify subresource hosts against known bot-management / CAPTCHA vendors.

Not exhaustive — the intent is to surface the WAF-adjacent vendors a WaaS
customer is most likely to be running today. Add entries as we see them
in real customer profiles.
"""

from app.profiler.schemas import BotVendor

# host substring → (display name)
BOT_VENDOR_HOSTS: list[tuple[str, str]] = [
    ('www.google.com/recaptcha', 'reCAPTCHA'),
    ('recaptcha.net', 'reCAPTCHA'),
    ('gstatic.com/recaptcha', 'reCAPTCHA'),
    ('hcaptcha.com', 'hCaptcha'),
    ('newassets.hcaptcha.com', 'hCaptcha'),
    ('challenges.cloudflare.com', 'Cloudflare Turnstile'),
    ('datadome.co', 'DataDome'),
    ('datado.me', 'DataDome'),
    ('js.datadome.co', 'DataDome'),
    ('perimeterx.net', 'PerimeterX / HUMAN'),
    ('px-cdn.net', 'PerimeterX / HUMAN'),
    ('kasada.io', 'Kasada'),
    ('ct.kasadacdn.com', 'Kasada'),
    ('akstat.io', 'Akamai Bot Manager'),
    ('akamaihd.net/bot', 'Akamai Bot Manager'),
    ('cdn.jsdelivr.net/npm/@fingerprintjs', 'Fingerprint.js'),
    ('api.fpjs.io', 'Fingerprint.js'),
    ('shieldsquare.com', 'Radware Bot Manager'),
    ('bot-shield.com', 'Radware Bot Manager'),
    ('imperva.com/inc', 'Imperva Advanced Bot Protection'),
    ('imperva.js', 'Imperva Advanced Bot Protection'),
]


def classify(subresource_hosts_with_urls: list[tuple[str, str]]) -> list[BotVendor]:
    """Return a deduplicated list of vendors detected from any URL.

    Input is (host, url) pairs so we can match on either the bare host
    (`hcaptcha.com`) or a host+path prefix (`www.google.com/recaptcha`).
    """
    seen: dict[str, BotVendor] = {}
    for host, url in subresource_hosts_with_urls:
        haystack = f'{host}{url}' if url.startswith('http') else url
        haystack_lc = haystack.lower()
        host_lc = (host or '').lower()
        for needle, display in BOT_VENDOR_HOSTS:
            if needle in haystack_lc or needle in host_lc:
                if display not in seen:
                    seen[display] = BotVendor(name=display, evidence=host or url)
                break
    return list(seen.values())
