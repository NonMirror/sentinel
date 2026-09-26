"""漏洞靶场 + WAF 反向代理 命令行入口 (mise task: lab)."""
from __future__ import annotations

import argparse
import time

from ..core.config import Config
from ..runtime import SentinelRuntime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel 靶场 + 反向代理")
    parser.add_argument("--port", type=int, default=None, help="代理监听端口")
    parser.add_argument("--instances", type=int, default=None, help="靶场实例数")
    parser.add_argument("--mode", default=None, choices=["block", "detect", "off"])
    args = parser.parse_args(argv)

    config = Config()
    if args.port is not None:
        config.listener.port = args.port
    if args.instances is not None:
        config.lab.instances = args.instances
        config.backends = config.backends[:args.instances]
    if args.mode:
        config.waf.mode = args.mode

    runtime = SentinelRuntime(config).start()
    print("=" * 68)
    print(" Sentinel 轻量级防火墙 + 漏洞靶场 已启动")
    print(f"  反向代理入口 : http://{config.listener.host}:{runtime.proxy_port}")
    for url in runtime.lab_urls():
        print(f"  后端靶场      : {url}")
    print(f"  WAF 模式      : {config.waf.mode} | 规则数: {len(runtime.engine.ruleset)}")
    print("  Ctrl+C 退出")
    print("=" * 68)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 正在停止 ...")
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
