"""Sentinel 命令行入口.

    python -m sentinel            # 启动 TUI 管理平台 (默认)
    python -m sentinel tui
    python -m sentinel run        # 靶场 + WAF 代理 (无界面)
    python -m sentinel scan URL   # 一次性漏洞扫描
    python -m sentinel report     # 生成中文测试报告
    python -m sentinel version
    python -m sentinel vendor          # 内置第三方资产概览 (不完整则返回码 1)
"""
from __future__ import annotations

import argparse
import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel 综合安全平台")
    parser.add_argument("command", nargs="?", default="tui",
                        choices=["tui", "run", "scan", "report", "version", "lab", "vendor"])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--mode", default=None, choices=["block", "detect", "off"])
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--all", action="store_true",
                        help="使用全部扫描引擎融合扫描 (nuclei + w13scan + 内置)")
    parser.add_argument("--engines", default=None,
                        help="逗号分隔的引擎列表, 例如 nuclei,w13scan,builtin")
    parser.add_argument("--engine", default=None,
                        help="WAF 引擎 (modsecurity/naxsi/python 为原生; "
                             "nginx-modsecurity/nginx-naxsi 为可选参考数据面; "
                             "默认自动选择)")
    ns = parser.parse_args(argv)

    if ns.command == "version":
        print(f"Sentinel {__version__}")
        return 0

    if ns.command == "vendor":
        from .vendor import missing, summary
        data = summary()
        for item in data["collections"]:
            mark = "OK " if item["present"] else "缺失"
            size = item["bytes"] / 1024 / 1024
            print(f"[{mark}] {item['key']:<18} {item['files']:>6} 文件  "
                  f"{size:>6.1f} MiB  {item['license']:<12} {item['upstream']}")
        absent = missing()
        if absent:
            print(f"缺失集合: {', '.join(absent)} —— 请运行 tools/vendor.py",
                  file=sys.stderr)
            return 1
        totals = data["totals"]
        print(f"合计 {totals['files']} 文件 / "
              f"{totals['bytes'] / 1024 / 1024:.1f} MiB —— 完整")
        return 0

    if ns.command == "tui":
        from .core.config import Config
        from .tui import run
        config = Config()
        if ns.port:
            config.listener.port = ns.port
        if ns.mode:
            config.waf.mode = ns.mode
        run(config, engine=ns.engine)
        return 0

    if ns.command in ("run", "lab"):
        from .lab.cli import main as lab_main
        return lab_main([])

    if ns.command == "scan":
        from .core.config import load_config
        from .runtime import SentinelRuntime
        from .scanner.report import write_report
        config = load_config(None)
        url = ns.args[0] if ns.args else "http://127.0.0.1:8080/"
        runtime = SentinelRuntime(config, engine=ns.engine).start()
        print(f"[*] WAF 引擎: {runtime.engine_name}  "
              f"入口 :{runtime.front_port}  扫描目标: {url}")
        if ns.all or ns.engines:
            engines = [e.strip() for e in ns.engines.split(",")] if ns.engines else None
            targets = runtime.scan_targets(url)
            outcome = runtime.scan_multi(targets, engines=engines, deep=ns.deep)
            for run in outcome.runs:
                flag = "OK " if run.ok else "FAIL"
                print(f"    [{flag}] {run.engine:<8} 发现 {run.findings:<3} "
                      f"{run.seconds:6.1f}s {run.error[:40]}")
            report = runtime.last_report
            assert report is not None
            paths = write_report(report, "reports", "sentinel-multiscan")
            print(f"[+] 融合去重后 {report.stats.findings} 个漏洞, "
                  f"风险评分 {report.risk_score} ({report.risk_level})")
            for path in paths.values():
                print(f"    报告: {path}")
            runtime.stop()
            return 0
        report = runtime.scan(url, deep=ns.deep)
        paths = write_report(report, "reports", "sentinel-scan")
        print(f"[+] 发现 {report.stats.findings} 个漏洞, 风险评分 {report.risk_score} "
              f"({report.risk_level})")
        for path in paths.values():
            print(f"    报告: {path}")
        runtime.stop()
        return 0

    if ns.command == "report":
        from .reporting import generate_test_report
        generate_test_report()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
