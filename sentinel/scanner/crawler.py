"""目标识别模块 — 资产/接口/参数发现.

输入种子 URL, 输出可扫描的 :class:`Target` (端点 + 参数 + 表单), 并识别服务指纹.
纯标准库实现 (html.parser), 支持 robots.txt / sitemap.xml / 页面链接 / 表单 / JS 端点提取.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

from .client import HttpClient

FORM_PARAM_HINTS = ("q", "id", "name", "file", "url", "next", "callback", "path",
                    "page", "search", "query", "redirect", "return", "to", "target",
                    "filename", "img", "content", "data", "domain", "share")

JS_ENDPOINT_RE = re.compile(r"""["'`]([/][A-Za-z0-9_\-./?=&%]{2,120})["'`]""")
TECH_SIGNATURES = {
    "PHP": ("x-powered-by: php",),
    "Python": ("server: labhttp", "x-powered-by: flask", "server: werkzeug"),
    "Java": ("server: apache-coyote", "jsessionid"),
    "nginx": ("server: nginx",),
    "Express": ("x-powered-by: express",),
}


@dataclass(slots=True)
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    form_fields: list[str] = field(default_factory=list)
    source: str = "crawl"

    @property
    def key(self) -> str:
        parts = urlsplit(self.url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


@dataclass
class Target:
    base_url: str
    host: str
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    robots: list[str] = field(default_factory=list)
    title: str = ""
    status: int = 0

    def add(self, url: str, method: str = "GET", params: list[str] | None = None,
            form_fields: list[str] | None = None, source: str = "crawl") -> None:
        parts = urlsplit(url)
        if not parts.scheme:
            url = urljoin(self.base_url, url)
            parts = urlsplit(url)
        if parts.netloc and parts.netloc != urlsplit(self.base_url).netloc:
            return
        clean = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        ep = self.endpoints.get(clean)
        if ep is None:
            ep = Endpoint(url=clean, method=method, source=source)
            self.endpoints[clean] = ep
        if params:
            ep.params = sorted(set(ep.params) | set(params))
        if form_fields:
            ep.form_fields = sorted(set(ep.form_fields) | set(form_fields))
            ep.method = method

    @property
    def url_count(self) -> int:
        return len(self.endpoints)

    @property
    def param_count(self) -> int:
        return sum(len(e.params) + len(e.form_fields) for e in self.endpoints.values())

    def injectable(self) -> list[tuple[Endpoint, str, str]]:
        """返回 (端点, 参数名, 注入位置) 三元组; 位置为 query|form."""
        out: list[tuple[Endpoint, str, str]] = []
        for ep in self.endpoints.values():
            for param in ep.params:
                out.append((ep, param, "query"))
            for param in ep.form_fields:
                out.append((ep, param, "form"))
        return out


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[tuple[str, str, list[str]]] = []
        self.scripts: list[str] = []
        self._form: dict | None = None
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"])
        elif tag == "form":
            self._form = {"action": data.get("action", ""),
                          "method": (data.get("method") or "GET").upper(), "fields": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if data.get("name"):
                self._form["fields"].append(data["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append((self._form["action"], self._form["method"],
                               self._form["fields"]))
            self._form = None
        elif tag == "title":
            self.title = self.title.strip()

    def handle_data(self, data: str) -> None:
        if not self.title:
            self.title = data.strip()[:120]


class TargetRecognizer:
    """目标识别: 指纹 + 接口 + 参数."""

    def __init__(self, client: HttpClient, max_urls: int = 400, max_depth: int = 3,
                 include_paths: tuple[str, ...] = ()) -> None:
        self.client = client
        self.max_urls = max_urls
        self.max_depth = max_depth
        self.include_paths = include_paths

    def recognize(self, seed_url: str) -> Target:
        target = Target(base_url=seed_url, host=urlsplit(seed_url).netloc)
        seed = self.client.get(seed_url)
        target.status = seed.status
        target.server = seed.header("Server")

        hay = (seed.header_text + "\n" + seed.text[:8000]).lower()
        for tech, needles in TECH_SIGNATURES.items():
            if any(n in hay for n in needles):
                target.technologies.append(tech)

        parser = _LinkFormParser()
        try:
            parser.feed(seed.text)
        except Exception:
            pass
        target.title = parser.title

        seed_parts = urlsplit(seed_url)
        seed_params = list(parse_qs(seed_parts.query).keys())
        target.add(urlunsplit(seed_parts[:3] + ("", "")), params=seed_params,
                   source="seed")

        # robots.txt
        root = f"{urlsplit(seed_url).scheme}://{urlsplit(seed_url).netloc}"
        robots = self.client.get(root + "/robots.txt")
        if robots.status == 200:
            for line in robots.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        target.robots.append(path)

        # sitemap.xml
        sitemap = self.client.get(root + "/sitemap.xml")
        if sitemap.status == 200:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap.text):
                target.add(loc, source="sitemap")

        queue: list[tuple[str, int]] = [(seed_url, 0)]
        for path in target.robots + list(self.include_paths):
            queue.append((urljoin(root + "/", path.lstrip("/")), 1))

        visited: set[str] = set()
        while queue and target.url_count < self.max_urls:
            url, depth = queue.pop(0)
            norm = urlunsplit(urlsplit(url)[:3] + (urlsplit(url).query, ""))
            if norm in visited or depth > self.max_depth:
                continue
            visited.add(norm)

            if depth > 0:
                page = self.client.get(url)
                if page.status == 0:
                    continue
                html_text = page.text
            else:
                html_text = seed.text

            page_parser = _LinkFormParser()
            try:
                page_parser.feed(html_text)
            except Exception:
                pass

            for href in page_parser.links:
                absolute = urljoin(url, href)
                if urlsplit(absolute).scheme not in ("http", "https"):
                    continue
                params = list(parse_qs(urlsplit(absolute).query).keys())
                target.add(absolute, params=params, source="crawl")
                if params:
                    for param in params:
                        target.add(urlunsplit(urlsplit(absolute)[:3] + ("", "")),
                                   params=[param], source="crawl")
                if urlunsplit(urlsplit(absolute)[:3] + ("", "")) not in visited:
                    queue.append((absolute, depth + 1))

            for action, method, fields in page_parser.forms:
                absolute = urljoin(url, action or url)
                target.add(absolute, method=method, form_fields=fields, source="form")

            for endpoint in JS_ENDPOINT_RE.findall(html_text):
                absolute = urljoin(url, endpoint)
                params = list(parse_qs(urlsplit(absolute).query).keys())
                if params:
                    target.add(absolute, params=params, source="js")

        return target
