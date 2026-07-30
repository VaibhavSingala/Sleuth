"""Technology fingerprinting from passively observed signals.

Every detection carries the evidence that produced it, so a reader can judge
it rather than trust it. Absence of a signal never proves absence of the
technology -- plenty of stacks are invisible from outside.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .probe import Probe

# Harvest every URL referenced by the markup: script/img/link sources plus
# anything quoted that looks like a URL. Good enough for fingerprinting.
_URL_RE = re.compile(r"""["'(\s](https?://[^"'()\s>]{4,300}|/[^"'()\s>]{2,200})""")
_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", re.I
)


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    headers: tuple = ()      # (header, value-regex or "" for presence)
    cookies: tuple = ()      # regex on cookie name
    html: tuple = ()         # regex in raw HTML
    urls: tuple = ()         # regex on any referenced URL
    generator: str = ""      # regex on <meta name=generator>
    dns: tuple = ()          # regex on any DNS record value


@dataclass
class Detection:
    name: str
    category: str
    evidence: list = field(default_factory=list)


# --- Signature table ------------------------------------------------------
# Ordered by category for readability; matching order does not matter.
SIGNATURES = (
    # CDN / edge
    Signature("Cloudflare", "CDN / edge", headers=(("cf-ray", ""), ("cf-cache-status", "")),
              dns=(r"\.cloudflare\.com", r"ns\d*\.cloudflare")),
    Signature("Fastly", "CDN / edge", headers=(("x-served-by", r"cache-"), ("x-fastly", "")),
              dns=(r"fastly",)),
    Signature("Amazon CloudFront", "CDN / edge", headers=(("x-amz-cf-id", ""), ("via", r"CloudFront")),
              dns=(r"cloudfront\.net",)),
    Signature("Akamai", "CDN / edge", headers=(("x-akamai-transformed", ""), ("server", r"AkamaiGHost")),
              dns=(r"akamai(edge|technologies)?\.net",)),
    Signature("Vercel", "CDN / edge", headers=(("x-vercel-id", ""), ("server", r"^Vercel")),
              dns=(r"vercel-dns|vercel\.app",)),
    Signature("Netlify", "CDN / edge", headers=(("x-nf-request-id", ""), ("server", r"Netlify")),
              dns=(r"netlify",)),
    Signature("Bunny CDN", "CDN / edge", headers=(("server", r"BunnyCDN"),)),
    Signature("Imperva / Incapsula", "CDN / edge", cookies=(r"^incap_ses", r"^visid_incap")),
    Signature("Sucuri", "CDN / edge", headers=(("x-sucuri-id", ""),)),

    # Cloud / hosting
    Signature("Amazon S3", "Hosting", headers=(("server", r"AmazonS3"),)),
    Signature("Amazon Web Services", "Hosting", headers=(("x-amz-request-id", ""),),
              dns=(r"amazonaws\.com",)),
    Signature("Google Cloud", "Hosting", headers=(("server", r"Google Frontend|gws"),),
              dns=(r"googlehosted|1e100\.net",)),
    Signature("Microsoft Azure", "Hosting", headers=(("x-azure-ref", ""), ("x-msedge-ref", "")),
              dns=(r"azure(websites|edge|fd)|trafficmanager\.net",)),
    Signature("GitHub Pages", "Hosting", headers=(("server", r"GitHub\.com"),),
              dns=(r"github\.io",)),
    Signature("Heroku", "Hosting", headers=(("via", r"vegur"),), dns=(r"herokuapp|herokudns",)),
    Signature("DigitalOcean", "Hosting", dns=(r"digitalocean",)),
    Signature("Shopify", "Hosting", headers=(("x-shopid", ""), ("x-shopify-stage", "")),
              dns=(r"shops\.myshopify\.com|shopify",)),

    # Web servers
    Signature("nginx", "Web server", headers=(("server", r"nginx"),)),
    Signature("Apache", "Web server", headers=(("server", r"Apache"),)),
    Signature("Microsoft IIS", "Web server", headers=(("server", r"Microsoft-IIS"),)),
    Signature("LiteSpeed", "Web server", headers=(("server", r"LiteSpeed"),)),
    Signature("Caddy", "Web server", headers=(("server", r"Caddy"),)),
    Signature("Envoy", "Web server", headers=(("server", r"envoy"),)),

    # Backend language / framework
    Signature("PHP", "Backend", headers=(("x-powered-by", r"PHP"),), cookies=(r"^PHPSESSID",)),
    Signature("ASP.NET", "Backend", headers=(("x-aspnet-version", ""), ("x-powered-by", r"ASP\.NET")),
              cookies=(r"^ASP\.NET_SessionId",)),
    Signature("Java / servlet", "Backend", cookies=(r"^JSESSIONID",)),
    Signature("Ruby on Rails", "Backend", cookies=(r"_session$|^_rails",),
              headers=(("x-runtime", ""),)),
    Signature("Django", "Backend", cookies=(r"^csrftoken$", r"^django"),),
    Signature("Laravel", "Backend", cookies=(r"^laravel_session", r"^XSRF-TOKEN$")),
    Signature("Express", "Backend", headers=(("x-powered-by", r"Express"),)),
    Signature("Flask / Werkzeug", "Backend", headers=(("server", r"Werkzeug"),)),
    # x-request-id deliberately not used here -- far too many stacks emit it.
    Signature("Phoenix / Elixir", "Backend", cookies=(r"_phoenix",)),

    # Frontend frameworks
    Signature("Next.js", "Frontend", html=(r"__NEXT_DATA__", r"/_next/static"),
              headers=(("x-nextjs-cache", ""),)),
    Signature("Nuxt", "Frontend", html=(r"__NUXT__", r"/_nuxt/")),
    Signature("React", "Frontend", html=(r"data-reactroot|data-reactid|__REACT_DEVTOOLS",)),
    Signature("Vue.js", "Frontend", html=(r"data-v-[0-9a-f]{8}|__VUE__|v-cloak",)),
    Signature("Angular", "Frontend", html=(r"ng-version=|_nghost-|_ngcontent-",)),
    Signature("Svelte / SvelteKit", "Frontend", html=(r"svelte-[0-9a-z]{6}|__sveltekit",)),
    Signature("Astro", "Frontend", html=(r"astro-island|_astro/",)),
    Signature("jQuery", "Frontend", urls=(r"jquery[.-]",)),
    Signature("Bootstrap", "Frontend", urls=(r"bootstrap(\.min)?\.(js|css)",)),
    Signature("Tailwind CSS", "Frontend", html=(r'class="[^"]*\b(?:flex|grid)\b[^"]*\b(?:px-\d|py-\d|mt-\d)',)),
    Signature("HTMX", "Frontend", html=(r"hx-get=|hx-post=|htmx\.org",)),
    Signature("Alpine.js", "Frontend", html=(r"x-data=|alpinejs",)),

    # CMS / site builders
    Signature("WordPress", "CMS", generator=r"WordPress", html=(r"/wp-content/", r"/wp-includes/")),
    Signature("Drupal", "CMS", generator=r"Drupal", headers=(("x-drupal-cache", ""),)),
    Signature("Joomla", "CMS", generator=r"Joomla"),
    Signature("Ghost", "CMS", generator=r"Ghost"),
    Signature("Wix", "CMS", generator=r"Wix", html=(r"static\.wixstatic\.com",)),
    Signature("Squarespace", "CMS", generator=r"Squarespace", html=(r"squarespace\.com",)),
    Signature("Webflow", "CMS", generator=r"Webflow", html=(r"wf-domain|webflow\.js",)),
    Signature("Contentful", "CMS", urls=(r"ctfassets\.net",)),
    Signature("Sanity", "CMS", urls=(r"cdn\.sanity\.io",)),
    Signature("Hugo", "CMS", generator=r"Hugo"),
    Signature("Jekyll", "CMS", generator=r"Jekyll"),
    Signature("Framer", "CMS", generator=r"Framer", html=(r"framerusercontent",)),

    # Ecommerce
    Signature("Shopify (storefront)", "Ecommerce", html=(r"cdn\.shopify\.com", r"Shopify\.theme")),
    Signature("WooCommerce", "Ecommerce", html=(r"woocommerce",)),
    Signature("Magento", "Ecommerce", html=(r"/static/version\d+/frontend/|Magento_",)),
    Signature("BigCommerce", "Ecommerce", html=(r"bigcommerce\.com",)),

    # Analytics / tag management
    Signature("Google Tag Manager", "Analytics", urls=(r"googletagmanager\.com/gtm\.js",)),
    Signature("Google Analytics 4", "Analytics", urls=(r"googletagmanager\.com/gtag/js",)),
    Signature("Google Analytics (legacy)", "Analytics", urls=(r"google-analytics\.com/(analytics|ga)\.js",)),
    Signature("Plausible", "Analytics", urls=(r"plausible\.io/js",)),
    Signature("Fathom", "Analytics", urls=(r"usefathom\.com",)),
    Signature("Matomo", "Analytics", urls=(r"matomo\.(js|php)|piwik\.",)),
    Signature("Segment", "Analytics", urls=(r"cdn\.segment\.(com|io)",)),
    Signature("Mixpanel", "Analytics", urls=(r"mixpanel",)),
    Signature("Amplitude", "Analytics", urls=(r"amplitude\.com",)),
    Signature("Hotjar", "Analytics", urls=(r"static\.hotjar\.com",)),
    Signature("Microsoft Clarity", "Analytics", urls=(r"clarity\.ms",)),
    Signature("Cloudflare Web Analytics", "Analytics", urls=(r"static\.cloudflareinsights\.com",)),
    Signature("Meta Pixel", "Analytics", urls=(r"connect\.facebook\.net",)),
    Signature("LinkedIn Insight", "Analytics", urls=(r"snap\.licdn\.com",)),
    Signature("TikTok Pixel", "Analytics", urls=(r"analytics\.tiktok\.com",)),

    # Marketing / CRM / support
    Signature("HubSpot", "Marketing / CRM", urls=(r"js\.hs-scripts\.com|hsforms\.net",)),
    Signature("Marketo", "Marketing / CRM", urls=(r"munchkin\.marketo",)),
    Signature("Salesforce / Pardot", "Marketing / CRM", urls=(r"pardot\.com|force\.com",)),
    Signature("Intercom", "Marketing / CRM", urls=(r"widget\.intercom\.io|intercomcdn",)),
    Signature("Zendesk", "Marketing / CRM", urls=(r"zdassets\.com|zendesk\.com",)),
    Signature("Drift", "Marketing / CRM", urls=(r"js\.driftt\.com",)),
    Signature("Mailchimp", "Marketing / CRM", urls=(r"chimpstatic\.com|list-manage\.com",)),
    Signature("Klaviyo", "Marketing / CRM", urls=(r"klaviyo\.com",)),

    # Payments / auth / infra
    Signature("Stripe", "Payments", urls=(r"js\.stripe\.com",)),
    Signature("PayPal", "Payments", urls=(r"paypal(objects)?\.com",)),
    Signature("Razorpay", "Payments", urls=(r"checkout\.razorpay\.com",)),
    Signature("Braintree", "Payments", urls=(r"braintreegateway\.com",)),
    Signature("Auth0", "Auth", urls=(r"auth0\.com",)),
    Signature("Okta", "Auth", urls=(r"okta(cdn)?\.com",)),
    Signature("Firebase", "Backend service", urls=(r"firebase(io|app)?\.com|googleapis\.com/identitytoolkit",)),
    Signature("Supabase", "Backend service", urls=(r"supabase\.(co|io)",)),
    Signature("Algolia", "Backend service", urls=(r"algolia(net)?\.(com|net)",)),
    Signature("Sentry", "Error tracking", urls=(r"sentry[.-]|browser\.sentry-cdn",)),
    Signature("Datadog RUM", "Error tracking", urls=(r"datadoghq|datadog-browser",)),
    Signature("New Relic", "Error tracking", html=(r"NREUM|newrelic",)),
    Signature("LaunchDarkly", "Feature flags", urls=(r"launchdarkly\.com",)),
    Signature("reCAPTCHA", "Security", urls=(r"google\.com/recaptcha|gstatic\.com/recaptcha",)),
    Signature("hCaptcha", "Security", urls=(r"hcaptcha\.com",)),
    Signature("Cloudflare Turnstile", "Security", urls=(r"challenges\.cloudflare\.com",)),

    # Media / fonts / maps
    Signature("Google Fonts", "Fonts / media", urls=(r"fonts\.(googleapis|gstatic)\.com",)),
    Signature("Font Awesome", "Fonts / media", urls=(r"fontawesome",)),
    Signature("Cloudinary", "Fonts / media", urls=(r"res\.cloudinary\.com",)),
    Signature("imgix", "Fonts / media", urls=(r"imgix\.net",)),
    Signature("YouTube embed", "Fonts / media", urls=(r"youtube(-nocookie)?\.com/embed",)),
    Signature("Vimeo embed", "Fonts / media", urls=(r"player\.vimeo\.com",)),
    Signature("Google Maps", "Fonts / media", urls=(r"maps\.google(apis)?\.com",)),
    Signature("Mapbox", "Fonts / media", urls=(r"mapbox\.com",)),
)

# Mail and DNS providers, read from MX / NS records.
MAIL_PROVIDERS = (
    (r"google|googlemail|aspmx", "Google Workspace"),
    (r"outlook|microsoft|office365", "Microsoft 365"),
    (r"zoho", "Zoho Mail"),
    (r"protonmail|proton\.me", "Proton Mail"),
    (r"mimecast", "Mimecast"),
    (r"proofpoint|pphosted", "Proofpoint"),
    (r"messagingengine", "Fastmail"),
    (r"secureserver", "GoDaddy"),
    (r"amazonses|amazonaws", "Amazon SES"),
    (r"mailgun", "Mailgun"),
    (r"sendgrid", "SendGrid"),
)

DNS_PROVIDERS = (
    (r"cloudflare", "Cloudflare DNS"),
    (r"awsdns", "Amazon Route 53"),
    (r"azure-dns", "Azure DNS"),
    (r"googledomains|google", "Google Cloud DNS"),
    (r"domaincontrol", "GoDaddy DNS"),
    (r"nsone|ns1", "NS1"),
    (r"dnsimple", "DNSimple"),
    (r"digitalocean", "DigitalOcean DNS"),
    (r"vercel-dns", "Vercel DNS"),
    (r"registrar-servers", "Namecheap"),
)

SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS — forces HTTPS on repeat visits"),
    ("content-security-policy", "CSP — restricts what the page may load/execute"),
    ("x-frame-options", "Clickjacking protection (superseded by CSP frame-ancestors)"),
    ("x-content-type-options", "Stops MIME-type sniffing"),
    ("referrer-policy", "Controls how much referrer data leaks outbound"),
    ("permissions-policy", "Gates camera/mic/geolocation APIs"),
    ("cross-origin-opener-policy", "Isolates the browsing context"),
)


def _referenced_urls(html: str) -> list:
    return [m.group(1) for m in _URL_RE.finditer(html)]


def _match(sig: Signature, probe: Probe, urls: list, generator: str) -> list:
    """Return the evidence strings that make this signature fire."""
    evidence = []

    for header, pattern in sig.headers:
        value = probe.header(header)
        if value and (not pattern or re.search(pattern, value, re.I)):
            evidence.append(f"header `{header}: {value[:80]}`")

    for pattern in sig.cookies:
        for name in probe.cookies:
            if re.search(pattern, name, re.I):
                evidence.append(f"cookie `{name}`")

    for pattern in sig.html:
        if re.search(pattern, probe.html, re.I):
            evidence.append(f"markup matches `{pattern}`")

    for pattern in sig.urls:
        for url in urls:
            if re.search(pattern, url, re.I):
                evidence.append(f"loads `{url[:90]}`")
                break

    if sig.generator and generator and re.search(sig.generator, generator, re.I):
        evidence.append(f"meta generator `{generator[:60]}`")

    for pattern in sig.dns:
        for values in probe.dns.values():
            if any(re.search(pattern, v, re.I) for v in values):
                evidence.append(f"DNS record matches `{pattern}`")
                break

    return evidence


def detect(probe: Probe) -> list:
    """Run every signature against the probe. Returns detections with evidence."""
    urls = _referenced_urls(probe.html)
    generator_match = _GENERATOR_RE.search(probe.html)
    generator = generator_match.group(1) if generator_match else ""

    detections = []
    for sig in SIGNATURES:
        evidence = _match(sig, probe, urls, generator)
        if evidence:
            detections.append(Detection(sig.name, sig.category, evidence[:3]))
    return detections


def _provider_from(records: list, table: tuple) -> list:
    found = []
    for pattern, label in table:
        if any(re.search(pattern, value, re.I) for value in records):
            if label not in found:
                found.append(label)
    return found


def mail_providers(probe: Probe) -> list:
    return _provider_from(probe.dns.get("MX", []), MAIL_PROVIDERS)


def dns_providers(probe: Probe) -> list:
    return _provider_from(probe.dns.get("NS", []), DNS_PROVIDERS)


def security_posture(probe: Probe) -> tuple:
    """Split the standard security headers into present and absent.

    Informational only: it reports what the server already advertises in every
    response. Absence is not a vulnerability claim -- plenty of sites are fine
    without some of these.
    """
    present, absent = [], []
    for header, why in SECURITY_HEADERS:
        value = probe.header(header)
        if value:
            present.append((header, value[:120]))
        else:
            absent.append((header, why))
    return present, absent


def disclosed_versions(probe: Probe) -> list:
    """Version strings the server volunteers about itself."""
    out = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = probe.header(header)
        if value and re.search(r"\d+\.\d+", value):
            out.append(f"`{header}: {value[:80]}`")
    return out
