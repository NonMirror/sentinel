"""QingScan 主动扫描兼容层回归测试。"""
from __future__ import annotations

from urllib.parse import urlsplit

from sentinel.core.models import Severity
from sentinel.scanner.client import HttpResult
from sentinel.scanner.crawler import Endpoint, Target, TargetRecognizer
from sentinel.scanner.plugins.base import PluginContext
from sentinel.scanner.plugins.cors import Cors
from sentinel.scanner.plugins.disclosure import DirectoryBrowse
from sentinel.scanner.plugins.hygiene import ResponseHygiene
from sentinel.scanner.plugins.qingscan import QingScanExposure, QingScanWafDetect
from sentinel.scanner.qingscan import (
    QINGSCAN_DIR_PATHS,
    QINGSCAN_EXPOSURE_RULES,
    QINGSCAN_FINGERPRINTS,
    QINGSCAN_WAF_RULES,
    detect_qingscan_fingerprints,
)


class StubClient:
    def __init__(self, responses: dict[str, HttpResult]) -> None:
        self.responses = responses
        self.requested: list[str] = []

    def request(self, method: str, url: str, body=None, headers=None) -> HttpResult:
        self.requested.append(url)
        return self.responses.get(url, HttpResult(url=url, method=method, status=404))

    def get(self, url: str) -> HttpResult:
        return self.request("GET", url)


def _response(url: str, body: str, *, status: int = 200,
              content_type: str = "text/html") -> HttpResult:
    return HttpResult(url=url, method="GET", status=status,
                      headers={"Content-Type": content_type}, body=body.encode())


def test_qingscan_rule_inventory_matches_pinned_upstream():
    assert len(QINGSCAN_EXPOSURE_RULES) == 11
    assert len(QINGSCAN_DIR_PATHS) == 329
    assert len(QINGSCAN_FINGERPRINTS) == 55
    assert len(QINGSCAN_WAF_RULES) == 22
    assert {"admin", ".env", "druid/index.html", "nacos/", "v3/api-docs"} \
        <= set(QINGSCAN_DIR_PATHS)
    assert {rule.native_plugin for rule in QINGSCAN_EXPOSURE_RULES if rule.native_plugin} == {
        "phpinfo", "git_leak", "spring_actuator",
    }


def test_qingscan_fingerprint_semantics_preserve_header_and_body_rules():
    found = detect_qingscan_fingerprints(
        {"Server": "Werkzeug/3", "X-AspNet-Version": "4.0"},
        '<meta name="csrf-token"><div id="app">grafana-app</div>',
    )
    assert {"Flask", "ASP.NET", "laravel", "Vue.js", "Grafana"} <= set(found)
    assert "nginx" not in found


def test_qingscan_exposure_detects_missing_native_capabilities_and_soft404():
    root = "http://target.test"
    home = _response(root + "/", "same soft-404 page")
    responses = {
        root + "/": home,
        root + "/.env": _response(root + "/.env", "APP_ENV=prod\nDB_PASSWORD=secret"),
        root + "/web.config": _response(root + "/web.config", "<configuration>"),
        root + "/.htaccess": _response(root + "/.htaccess", "RewriteEngine On"),
        root + "/config/": _response(root + "/config/", "same soft-404 page"),
        root + "/db.sql": _response(root + "/db.sql", "binary",
                                     content_type="application/octet-stream"),
        root + "/WEB-INF/web.xml": _response(root + "/WEB-INF/web.xml", "<web-app>"),
        root + "/druid": _response(root + "/druid", "Druid Stat Index"),
        root + "/nacos/": _response(root + "/nacos/", "Nacos Console"),
        root + "/ftp/package.json.bak": _response(
            root + "/ftp/package.json.bak", '{"name":"app"}',
            content_type="application/octet-stream"),
        root + "/metrics": _response(
            root + "/metrics", "# HELP app_requests Total requests\n"
            "# TYPE app_requests counter\napp_requests 12",
            content_type="text/plain"),
        root + "/.gitignore": _response(
            root + "/.gitignore", "config/config.inc.php\nDockerfile\n*.swp",
            content_type="text/plain"),
    }
    client = StubClient(responses)
    target = Target(base_url=root + "/", host=urlsplit(root).netloc)
    target.add(root + "/ftp/package.json.bak", source="qingscan-dict")
    target.add(root + "/metrics", source="qingscan-dict")
    target.add(root + "/.gitignore", source="qingscan-dict")
    endpoint = Endpoint(root + "/")
    ctx = PluginContext(client=client, target=target, endpoint=endpoint)

    findings = QingScanExposure().run(ctx)
    types = {finding.vuln_type for finding in findings}
    assert {"backup_file", "path_traversal", "sensitive_config", "unauth",
            "metrics_exposure", "metadata_exposure"} <= types
    assert all(finding.severity in {Severity.LOW, Severity.MEDIUM, Severity.HIGH}
               for finding in findings)
    assert not any(finding.payload == "/config/" for finding in findings)
    assert root + "/info.php" not in client.requested
    assert root + "/.git/config" not in client.requested
    assert root + "/actuator" not in client.requested
    assert any(finding.url.endswith("/ftp/package.json.bak") for finding in findings)


def test_qingscan_directory_candidates_feed_discovered_endpoints_only():
    root = "http://target.test"
    home = _response(root + "/", "home", content_type="text/html")
    responses = {
        root + "/": home,
        root + "/robots.txt": _response(root + "/robots.txt", "", status=404),
        root + "/sitemap.xml": _response(root + "/sitemap.xml", "", status=404),
        root + "/admin": _response(root + "/admin", "<title>Admin</title>"),
        root + "/missing": _response(root + "/missing", "missing", status=404),
        root + "/soft": _response(root + "/soft", "home"),
    }
    target = TargetRecognizer(StubClient(responses), max_urls=8, max_depth=1,
                              include_paths=("admin", "missing", "soft")).recognize(root + "/")
    assert root + "/admin" in target.endpoints
    assert root + "/missing" not in target.endpoints
    assert root + "/soft" not in target.endpoints
    assert target.endpoints[root + "/admin"].source == "qingscan-dict"


def test_qingscan_directory_candidates_filter_shared_login_redirects():
    root = "http://target.test"
    login = _response(root + "/login", "login page")
    redirect = HttpResult(url=root + "/", method="GET", status=302,
                          headers={"Location": "/login"})
    responses = {
        root + "/": redirect,
        root + "/login": login,
        root + "/robots.txt": _response(root + "/robots.txt", "", status=404),
        root + "/sitemap.xml": _response(root + "/sitemap.xml", "", status=404),
        root + "/admin": HttpResult(url=root + "/admin", method="GET", status=302,
                                     headers={"Location": "/login"}),
    }
    target = TargetRecognizer(StubClient(responses), max_urls=8, max_depth=1,
                              include_paths=("admin",)).recognize(root + "/")
    assert root + "/admin" not in target.endpoints


def test_qingscan_directory_candidates_keep_unique_redirect_destination():
    root = "http://target.test"
    responses = {
        root + "/": _response(root + "/", "home"),
        root + "/robots.txt": _response(root + "/robots.txt", "", status=404),
        root + "/sitemap.xml": _response(root + "/sitemap.xml", "", status=404),
        root + "/api-docs": HttpResult(url=root + "/api-docs", method="GET", status=301,
                                        headers={"Location": "/api-docs/"}),
        root + "/api-docs/": _response(root + "/api-docs/", "<title>Swagger UI</title>"),
    }
    target = TargetRecognizer(StubClient(responses), max_urls=8, max_depth=1,
                              include_paths=("api-docs",)).recognize(root + "/")
    assert root + "/api-docs/" in target.endpoints
    assert root + "/api-docs" not in target.endpoints


def test_crawler_reads_spa_bundles_and_keeps_blank_query_parameters():
    root = "http://target.test"
    responses = {
        root + "/": _response(
            root + "/", '<script src="/app.js"></script>'
            '<img src="/dvwa/images/logo.png">'),
        root + "/robots.txt": _response(root + "/robots.txt", "", status=404),
        root + "/sitemap.xml": _response(root + "/sitemap.xml", "", status=404),
        root + "/app.js": _response(
            root + "/app.js",
            'let a="/api/Challenges/?key=nftMintChallenge";'
            'let b="/rest/user/security-question?email=";',
            content_type="application/javascript"),
        root + "/dvwa/images/logo.png": _response(
            root + "/dvwa/images/logo.png", "png", content_type="image/png"),
    }
    target = TargetRecognizer(StubClient(responses), max_urls=20, max_depth=2).recognize(
        root + "/")
    assert root + "/app.js" in target.endpoints
    assert root + "/dvwa/images/logo.png" in target.endpoints
    assert target.endpoints[root + "/api/Challenges/"].params == ["key"]
    assert target.endpoints[root + "/rest/user/security-question"].params == ["email"]


def test_response_hygiene_covers_nuclei_nikto_and_zap_observations():
    root = "http://target.test/"
    redirect = HttpResult(
        url=root, method="GET", status=302,
        headers={"Location": "/login", "Server": "Apache/2.4.25 (Debian)",
                 "Set-Cookie": "session=abc; Path=/"},
        header_items=[("Location", "/login"),
                      ("Server", "Apache/2.4.25 (Debian)"),
                      ("Set-Cookie", "session=abc; Path=/")])
    login = _response(root + "login", "<title>Login</title>")
    target = Target(base_url=root, host="target.test")
    findings = ResponseHygiene().run(PluginContext(
        client=StubClient({root: redirect, root + "login": login}),
        target=target, endpoint=Endpoint(root)))
    types = {finding.vuln_type for finding in findings}
    assert {"security_headers", "cookie_flags", "outdated_server"} <= types
    assert {finding.param for finding in findings if finding.vuln_type == "cookie_flags"} == {
        "session:httponly", "session:secure", "session:samesite",
    }


def test_qingscan_discovered_express_directory_listing_is_reported():
    root = "http://target.test"
    url = root + "/ftp"
    client = StubClient({url: _response(url, "<title>listing directory /ftp</title>")})
    target = Target(base_url=root + "/", host="target.test")
    target.add(url, source="qingscan-dict")
    findings = DirectoryBrowse().run(
        PluginContext(client=client, target=target, endpoint=target.endpoints[url]))
    assert len(findings) == 1
    assert findings[0].vuln_type == "directory_browse"


def test_asset_endpoint_prioritizes_its_nested_listing_parents():
    root = "http://target.test"
    asset = root + "/dvwa/images/logo.png"
    listing = root + "/dvwa/images/"
    client = StubClient({
        asset: _response(asset, "png", content_type="image/png"),
        listing: _response(listing, "<title>Index of /dvwa/images</title>"),
        root + "/dvwa/": _response(root + "/dvwa/", "<title>Index of /dvwa</title>"),
        root + "/": _response(root + "/", "home"),
    })
    target = Target(base_url=root + "/", host="target.test")
    target.add(asset, source="asset")
    findings = DirectoryBrowse().run(PluginContext(
        client=client, target=target, endpoint=target.endpoints[asset]))
    assert [finding.url for finding in findings] == [listing.rstrip("/")]


def test_wildcard_cors_is_retained_as_low_confidence_root_observation():
    root = "http://target.test/"
    client = StubClient({root: HttpResult(
        url=root, method="GET", status=200,
        headers={"Access-Control-Allow-Origin": "*"}, body=b"ok")})
    target = Target(base_url=root, host="target.test")
    findings = Cors().run(PluginContext(
        client=client, target=target, endpoint=Endpoint(root)))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].confidence == 0.75


def test_qingscan_waf_detection_uses_signature_before_active_probe():
    root = "http://target.test/"
    client = StubClient({
        root: HttpResult(url=root, method="GET", status=200,
                         headers={"Server": "Sucuri/Cloudproxy"}, body=b"ok"),
    })
    target = Target(base_url=root, host="target.test")
    findings = QingScanWafDetect().run(
        PluginContext(client=client, target=target, endpoint=Endpoint(root)))
    assert len(findings) == 1
    assert findings[0].vuln_type == "waf_detected"
    assert findings[0].severity is Severity.INFO
    assert "Sucuri" in findings[0].proof
    assert client.requested == [root]


def test_qingscan_waf_detection_preserves_active_probe_semantics():
    root = "http://target.test/"
    probe = root + "?a=1%27"
    client = StubClient({
        root: _response(root, "home"),
        probe: _response(probe, "Forbidden", status=403),
    })
    target = Target(base_url=root, host="target.test")
    findings = QingScanWafDetect().run(
        PluginContext(client=client, target=target, endpoint=Endpoint(root)))
    assert len(findings) == 1
    assert "200 -> 403" in findings[0].evidence
    assert client.requested == [root, probe]
