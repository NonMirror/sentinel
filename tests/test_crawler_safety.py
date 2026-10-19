"""爬虫访问边界测试；只使用内存响应，不发起扫描。"""
import pytest

from sentinel.scanner.client import HttpResult
from sentinel.scanner.crawler import Target, TargetRecognizer


class MemoryClient:
    def __init__(self, pages=None):
        self.pages = pages or {}
        self.requests = []

    def get(self, url):
        self.requests.append(url)
        return HttpResult(url=url, method="GET", status=200,
                          body=self.pages.get(url, "").encode())


@pytest.mark.parametrize("candidate", [
    "https://outside.test/page?q=1", "//outside.test/page?q=1",
    "http://example.test/page?q=1", "https://example.test:444/page?q=1",
    "https://user:password@example.test/page?q=1", "javascript:alert(1)",
    "https://[bad", "https://example.test:bad/", "/api/has space?q=1",
    '/api/"https:/github.com/test?q=1', "/api/%22broken?q=1",
    "/api/https:/github.com/test?q=1", "/api/bad%xx?q=1",
    "/api/bad\npath?q=1", "/api/bad\\path?q=1",
    "/logout.php", "/auth/sign-out", "/auth/sign-off", "/LOGOUT", "/%6cogout.php",
    "/account/delete/1", "/remove.php", "/index.php?action=logout",
])
def test_rejects_unsafe_endpoints(candidate):
    target = Target(base_url="https://example.test/", host="example.test")
    target.add(candidate, params=["q"])
    assert not target.endpoints


def test_all_discovery_sources_share_access_boundary():
    root = "https://example.test"
    client = MemoryClient({
        root + "/": '''
            <a href="/logout.php">Logout</a>
            <a href="https://outside.test/?q=1">Outside</a>
            <a href="/safe?q=1">Safe</a>
            <form action="/account/delete" method="post"><input name="id"></form>
            <script>const bad = "/remove.php?id=1";</script>
        ''',
        root + "/robots.txt": "Disallow: /logout.php\nDisallow: //outside.test/",
        root + "/sitemap.xml": "<loc>https://example.test/destroy?id=1</loc>",
    })
    target = TargetRecognizer(client, include_paths=("/delete", "//outside.test/")).recognize(root + "/")
    assert set(client.requests) == {root + path for path in (
        "/", "/robots.txt", "/sitemap.xml", "/safe?q=1")}
    assert set(target.endpoints) == {root + "/", root + "/safe"}


def test_js_requires_matching_quotes_and_rejects_escaped_fragments():
    root = "https://example.test"
    client = MemoryClient({root + "/": r'''
        const good = "/api/items?q=1";
        const mismatch = "/api/broken?q=1';
        const fragment = "prefix\"/api/fragment?q=1\"";
        const external = "//outside.test/api/items?q=1";
    '''})
    target = TargetRecognizer(client).recognize(root + "/")
    assert set(target.endpoints) == {root + "/", root + "/api/items"}


def test_default_port_and_encoded_business_path_are_allowed():
    target = Target(base_url="https://example.test/", host="example.test")
    target.add("https://example.test:443/files/report%202026.pdf")
    target.add("/catalog/remover")
    assert "https://example.test:443/files/report%202026.pdf" in target.endpoints
    assert "https://example.test/catalog/remover" in target.endpoints


def test_unsafe_seed_is_rejected_before_any_request():
    client = MemoryClient()
    with pytest.raises(ValueError, match="种子 URL"):
        TargetRecognizer(client).recognize("https://example.test/logout.php")
    assert client.requests == []
