"""Technology fingerprinting from one page: headers, cookie names and markup."""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegisscan.checks.base import Check
from aegisscan.engine import ScanContext
from aegisscan.htmlutil import meta_generator
from aegisscan.http import Response, http_evidence
from aegisscan.models import Finding, Severity, Target

_V = r"[/ ]?v?(\d+(?:\.\d+)*[\w.\-]*)?"


@dataclass(frozen=True)
class Technology:
    name: str
    version: str
    kind: str
    source: str

    def label(self) -> str:
        return f"{self.name} {self.version}".strip()


# (name, kind, pattern with an optional version group), matched against the Server header
_SERVER = [
    ("Apache HTTP Server", "web server", r"\bApache(?!-Coyote| Tomcat)" + _V),
    ("nginx", "web server", r"\bnginx" + _V),
    ("OpenResty", "web server", r"\bopenresty" + _V),
    ("Microsoft IIS", "web server", r"\bMicrosoft-IIS" + _V),
    ("LiteSpeed", "web server", r"\bLiteSpeed" + _V),
    ("Caddy", "web server", r"\bCaddy" + _V),
    ("Apache Tomcat", "application server", r"\b(?:Apache-Coyote|Apache Tomcat)" + _V),
    ("Jetty", "application server", r"\bJetty\(?" + _V),
    ("Kestrel", "web server", r"\bKestrel" + _V),
    ("Gunicorn", "application server", r"\bgunicorn" + _V),
    ("Werkzeug", "application server", r"\bWerkzeug" + _V),
    ("Uvicorn", "application server", r"\buvicorn" + _V),
    ("Cloudflare", "CDN", r"\bcloudflare" + _V),
    ("OpenSSL", "library", r"\bOpenSSL" + _V),
    ("PHP", "language", r"\bPHP" + _V),
    ("Python", "language", r"\bPython" + _V),
]
_POWERED_BY = [
    ("PHP", "language", r"\bPHP" + _V),
    ("ASP.NET", "framework", r"\bASP\.NET" + _V),
    ("Express", "framework", r"\bExpress" + _V),
    ("Next.js", "framework", r"\bNext\.js" + _V),
    ("Phusion Passenger", "application server", r"\bPhusion Passenger" + _V),
]
_VERSION_HEADERS = [
    ("x-aspnet-version", "ASP.NET", "framework"),
    ("x-aspnetmvc-version", "ASP.NET MVC", "framework"),
]
_COOKIES = [
    (r"^PHPSESSID$", "PHP", "language"),
    (r"^JSESSIONID$", "Java", "language"),
    (r"^ASP\.NET_SessionId$|^\.ASPXAUTH$", "ASP.NET", "framework"),
    (r"^laravel_session$", "Laravel", "framework"),
    (r"^csrftoken$|^django_language$", "Django", "framework"),
    (r"^connect\.sid$", "Express", "framework"),
    (r"^_rails_session$|^_session_id$", "Ruby on Rails", "framework"),
    (r"^wordpress_|^wp-settings-", "WordPress", "CMS"),
    (r"^ci_session$", "CodeIgniter", "framework"),
]
_MARKUP = [
    ("WordPress", "CMS", r"/wp-(?:content|includes)/"),
    ("Drupal", "CMS", r"/sites/(?:default|all)/(?:files|themes|modules)/|Drupal\.settings"),
    ("Joomla", "CMS", r"/media/jui/|/components/com_"),
    ("jQuery", "JavaScript library", r"jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min|\.slim)?\.js"),
    ("Bootstrap", "UI framework", r"bootstrap[@/.-](\d+\.\d+(?:\.\d+)?)"),
    ("Angular", "JavaScript framework", r'ng-version="(\d+[\d.]*)"'),
    ("AngularJS", "JavaScript framework", r"angular(?:js)?[/.-](1\.\d+(?:\.\d+)?)"),
    ("React", "JavaScript framework", r"data-reactroot|react(?:-dom)?[@/.-](\d+\.\d+(?:\.\d+)?)"),
    ("Next.js", "framework", r'id="__NEXT_DATA__"|/_next/static/'),
    ("Nuxt", "framework", r"window\.__NUXT__|/_nuxt/"),
    ("Vue.js", "JavaScript framework", r"vue(?:\.runtime)?[@/.-](\d+\.\d+(?:\.\d+)?)"),
]


def _first_group(match: re.Match[str]) -> str:
    return next((group for group in match.groups() if group), "")


def fingerprint(response: Response) -> list[Technology]:
    found: dict[str, Technology] = {}

    def add(name: str, version: str, kind: str, source: str) -> None:
        version = version.rstrip(".")
        known = found.get(name)
        if known is None or (version and not known.version):
            found[name] = Technology(name, version, kind, source)

    server = response.headers.get("server", "")
    for name, kind, pattern in _SERVER:
        match = re.search(pattern, server, re.I)
        if match:
            add(name, _first_group(match), kind, f"Server: {server}")
    powered = ", ".join(response.headers.get_list("x-powered-by"))
    for name, kind, pattern in _POWERED_BY:
        match = re.search(pattern, powered, re.I)
        if match:
            add(name, _first_group(match), kind, f"X-Powered-By: {powered}")
    for header, name, kind in _VERSION_HEADERS:
        value = response.headers.get(header)
        if value:
            add(name, value.strip(), kind, f"{header.title()}: {value}")
    generator_header = response.headers.get("x-generator")
    if generator_header:
        name, _, version = generator_header.partition(" ")
        add(name, version.split(" ")[0], "CMS", f"X-Generator: {generator_header}")

    for header in response.headers.get_list("set-cookie"):
        cookie_name = header.split("=", 1)[0].strip()
        for pattern, name, kind in _COOKIES:
            if re.search(pattern, cookie_name, re.I):
                add(name, "", kind, f"cookie name {cookie_name}")

    if response.is_html:
        text = response.text
        generator = meta_generator(text)
        if generator:
            match = re.match(r"(.+?)(?:\s+v?(\d[\w.\-]*))?$", generator.strip())
            if match:
                add(match.group(1), match.group(2) or "", "CMS", f"meta generator: {generator}")
        for name, kind, pattern in _MARKUP:
            match = re.search(pattern, text, re.I)
            if match:
                add(name, _first_group(match), kind, f"page markup: {match.group(0)[:60]}")
    return sorted(found.values(), key=lambda tech: (tech.kind, tech.name))


class TechnologyFingerprint(Check):
    id = "recon.fingerprint"
    title = "Technology fingerprinting"
    severity = Severity.INFO
    cwe = "CWE-200"
    owasp = "A05:2021 Security Misconfiguration"
    category = "recon"
    description = (
        "Web server, language, framework, CMS and JavaScript libraries, with versions, "
        "identified from headers, cookie names and page markup."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        response = await ctx.baseline()
        technologies = fingerprint(response)
        ctx.observe(
            "technologies",
            [
                {"technology": tech.name, "version": tech.version or "unknown", "type": tech.kind,
                 "identified from": tech.source}
                for tech in technologies
            ],
        )  # fmt: skip
        if not technologies:
            return []
        summary = ", ".join(tech.label() for tech in technologies)
        why = f"The response identifies the software behind the site: {summary}."
        listing = "\n".join(f"{tech.label():<28} {tech.source}" for tech in technologies)
        return [
            self.finding(
                title=f"Technology stack identified ({len(technologies)} components)",
                url=response.url,
                description=(
                    "Recon result, not a vulnerability in itself. It is the starting point for "
                    "checking each component against known vulnerabilities, and shows how much "
                    "the site reveals about itself. Version currency is not assessed here."
                ),
                why=why,
                evidence=[http_evidence(response, why, excerpt=listing)],
                remediation=(
                    "Keep every listed component on a supported, patched version, and remove "
                    "version banners where the platform allows it."
                ),
                severity=Severity.INFO,
            )
        ]
