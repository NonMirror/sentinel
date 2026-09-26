"""TUI 截图工具: 生成真实流量后逐面板导出 SVG/PNG.

用法:  env -u NO_COLOR TERM=xterm-256color COLORTERM=truecolor \\
           uv run python tools/capture_tui.py --out docs/tui
"""
from __future__ import annotations

import argparse
import asyncio
import os
import random
import shutil
import subprocess
import urllib.error
import urllib.request

from sentinel.core.config import Config
from sentinel.tui.app import SentinelTUI

BENIGN = ["/health", "/", "/search?q=laptop", "/product?id=2", "/page?name=guest",
          "/comments", "/api/user", "/api/orders", "/download?file=readme.txt",
          "/fetch?url=http://example.com/a", "/api/jsonp?callback=cb", "/go?next=/"]
ATTACK = ["/search?q=1+OR+1%3D1", "/search?q=1+UNION+SELECT+user+FROM+users",
          "/product?id=1+AND+SLEEP(0)", "/page?name=%3Cscript%3Ealert(1)%3C/script%3E",
          "/page?name=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
          "/download?file=../../../../etc/passwd", "/download?file=/etc/passwd",
          "/fetch?url=http://169.254.169.254/latest/meta-data/",
          "/fetch?url=file:///etc/passwd", "/.env", "/.git/config", "/admin",
          "/wp-login.php", "/phpmyadmin/index.php", "/actuator/env",
          "/ping?ip=127.0.0.1;cat+/etc/passwd",
          "/api/users?id=1'+OR+'1'='1", "/config/backup.zip", "/shell.php"]


def traffic(base: str, rounds: int = 14) -> tuple[int, int]:
    ok = blocked = 0
    for _ in range(rounds):
        for path in BENIGN:
            try:
                with urllib.request.urlopen(base + path, timeout=3) as resp:
                    resp.read()
                    ok += 1
            except urllib.error.HTTPError:
                blocked += 1
            except Exception:
                pass
        for path in ATTACK:
            try:
                with urllib.request.urlopen(base + path, timeout=3) as resp:
                    resp.read()
            except urllib.error.HTTPError:
                blocked += 1
            except Exception:
                pass
    return ok, blocked


def convert(svg_dir: str, names: list[str]) -> None:
    if not shutil.which("rsvg-convert"):
        return
    for name in names:
        svg = os.path.join(svg_dir, name + ".svg")
        png = os.path.join(svg_dir, name + ".png")
        if os.path.exists(svg):
            subprocess.run(["rsvg-convert", "-w", "1500", svg, "-o", png],
                           check=False, capture_output=True)


async def capture(out: str, size: tuple[int, int], deep_scan: bool) -> None:
    os.makedirs(out, exist_ok=True)
    cfg = Config()
    cfg.listener.host, cfg.listener.port = "127.0.0.1", 0
    cfg.waf.mode = "block"
    app = SentinelTUI(cfg)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        base = f"http://127.0.0.1:{app.runtime.proxy_port}"
        print(f"[*] 生成流量 {base} ...")
        ok, blocked = traffic(base, rounds=12)
        print(f"[+] 正常请求 {ok} / 被拦截 {blocked}")
        await pilot.pause(0.4)

        print("[*] 执行漏洞扫描 ...")
        app.run_command(f"scan http://127.0.0.1:{app.runtime.proxy_port}/")
        for _ in range(400):
            await pilot.pause(0.1)
            if app.runtime.last_report is not None:
                break
        report = app.runtime.last_report
        if report and deep_scan:
            app.run_command(f"scan! http://127.0.0.1:{app.runtime.proxy_port}/")
            for _ in range(400):
                await pilot.pause(0.1)
                if app.runtime.last_report and app.runtime.last_report.deep_scan:
                    break
        report = app.runtime.last_report
        if report:
            print(f"[+] 扫描完成: {report.stats.findings} 个漏洞, "
                  f"风险评分 {report.risk_score} ({report.risk_level})")
        app.run_command("report")
        await pilot.pause(0.3)

        names: list[str] = []
        labels = ["dashboard", "config", "ids", "rules", "audit", "scan", "vulndb",
                  "report", "engines"]
        for idx, label in enumerate(labels, 1):
            await pilot.press(str(idx))
            await pilot.pause(0.6)
            name = f"panel{idx}-{label}"
            app.save_screenshot(filename=name + ".svg", path=out)
            names.append(name)
            print(f"[+] 截图 {name}")

        # 帮助浮层
        await pilot.press("question_mark")
        await pilot.pause(0.4)
        app.save_screenshot(filename="help.svg", path=out)
        names.append("help")
        await pilot.press("escape")
        await pilot.pause(0.2)

        convert(out, names)
        print(f"[+] 已输出 {len(names)} 张截图到 {out}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="docs/tui")
    parser.add_argument("--cols", type=int, default=150)
    parser.add_argument("--rows", type=int, default=46)
    parser.add_argument("--deep", action="store_true")
    args = parser.parse_args()
    asyncio.run(capture(args.out, (args.cols, args.rows), args.deep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
