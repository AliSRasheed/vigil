"""Small HTML helpers. No JavaScript execution, no crawling: just reading one page."""

from __future__ import annotations

import contextlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

_URL_ATTRIBUTES = {"href", "src", "action", "data-src", "poster"}


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.generator: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        for name in _URL_ATTRIBUTES:
            if attributes.get(name):
                self.urls.append(attributes[name].strip())
        if tag == "meta" and attributes.get("name", "").lower() == "generator":
            self.generator = attributes.get("content") or None


def _parse(html: str) -> _PageParser:
    parser = _PageParser()
    with contextlib.suppress(Exception):  # malformed markup must never break a scan
        parser.feed(html)
    return parser


def extract_links(html: str, base_url: str) -> list[str]:
    """Absolute http(s) URLs referenced by a page, in document order, de-duplicated."""
    seen: dict[str, None] = {}
    for raw in _parse(html).urls:
        if raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        try:
            absolute = urljoin(base_url, raw)
            scheme = urlsplit(absolute).scheme
        except ValueError:
            continue
        if scheme in ("http", "https"):
            seen.setdefault(absolute.split("#", 1)[0], None)
    return list(seen)


def meta_generator(html: str) -> str | None:
    return _parse(html).generator
