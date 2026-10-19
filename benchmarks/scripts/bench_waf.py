"""Sentinel WAF 拦截能力 bench.

载荷来源:
  * GoTestWAF 测试用例 (owasp / owasp-api / community) + false-pos
  * PayloadsAllTheThings Intruder 字典
  * 项目自带良性语料 (含 "看起来像攻击" 的良性输入)

三个原生引擎各自对同一批请求判定, 统计分类拦截率 / 误报率 / 决策延迟.

    python bench_waf.py --out /tmp/opencode/results/waf.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import quote

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

import yaml  # noqa: E402

from benchmarks.corpus import build_corpus  # noqa: E402
from sentinel.core.config import Config  # noqa: E402
from sentinel.waf.engines import ENGINE_CLASSES  # noqa: E402
from sentinel.waf.parser import parse_request  # noqa: E402

#: 外部载荷语料根目录 (可用 SENTINEL_BENCH_PAYLOADS 覆盖)
PAYLOAD_DIR = Path(os.environ.get("SENTINEL_BENCH_PAYLOADS", "/tmp/opencode/payloads"))
PAYLOAD_ROOT = PAYLOAD_DIR / "gotestwaf" / "testcases"
PAT_ROOT = PAYLOAD_DIR / "PayloadsAllTheThings"
PAT_CATEGORIES = {
    "SQL Injection": "SQL Injection",
    "XSS Injection": "XSS",
    "Command Injection": "RCE",
    "Directory Traversal": "Path Traversal",
    "File Inclusion": "LFI",
    "XXE Injection": "XXE",
    "CRLF Injection": "CRLF Injection",
    "LDAP Injection": "LDAP Injection",
    "NoSQL Injection": "NoSQL Injection",
    "Open Redirect": "Open Redirect",
}
PAT_CAP = 250
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/128.0 Safari/537.36")
MAX_PAYLOAD = 4096


def _raw(method: str, target: str, headers: dict[str, str] | None = None,
         body: bytes = b"") -> bytes:
    base = {"Host": "target.local", "User-Agent": UA, "Accept": "*/*"}
    base.update(headers or {})
    if body:
        base.setdefault("Content-Type", "application/x-www-form-urlencoded")
        base["Content-Length"] = str(len(body))
    head = [f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in base.items()]
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


def _b(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


class Attack:
    __slots__ = ("raw", "category", "placement", "source")

    def __init__(self, raw: bytes, category: str, placement: str,
                 source: str = "") -> None:
        self.raw = raw
        self.category = category
        self.placement = placement
        self.source = source


# ── 载荷解析 ────────────────────────────────────────────────────────────
_ESC = {"\\'": "'", "\\\\": "\\", '\\"': '"'}


def tolerant_load(path: Path) -> tuple[list[str], str]:
    """GoTestWAF 的 YAML 含非标准转义 (``\\'``), 标准解析器会拒收.

    先做最小修复再走 safe_load; 仍失败则退回按行提取 ``payload:`` 列表.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    fixed = text.replace("\\'", "'")
    try:
        doc = yaml.safe_load(fixed)
        if isinstance(doc, dict):
            return [str(p) for p in (doc.get("payload") or [])], \
                str(doc.get("type") or path.stem).strip()
    except yaml.YAMLError:
        pass

    payloads: list[str] = []
    category = path.stem
    section = ""
    for line in text.splitlines():
        head = re.match(r"^(payload|encoder|placeholder|type):\s*(.*)$", line)
        if head:
            section, rest = head.group(1), head.group(2).strip()
            if section == "type" and rest:
                category = rest.strip('"\' ')
            continue
        if section != "payload":
            continue
        item = re.match(r"^\s*-\s?(.*)$", line)
        if not item:
            continue
        value = item.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            body = value[1:-1]
            for old, new in _ESC.items():
                body = body.replace(old, new)
            value = body
        payloads.append(value)
    return payloads, category


def load_payload_sets() -> dict[str, list[tuple[str, str]]]:
    """返回 {类别: [(载荷, 来源), ...]}, 合并 GoTestWAF 与 PayloadsAllTheThings."""
    sets: dict[str, list[tuple[str, str]]] = {}
    for yml in sorted(PAYLOAD_ROOT.rglob("*.yml")):
        if yml.parent.name == "false-pos" or "kb-" in yml.name:
            continue
        payloads, category = tolerant_load(yml)
        if payloads:
            sets.setdefault(category, []).extend(
                (p, "GoTestWAF") for p in payloads)

    for sub, category in PAT_CATEGORIES.items():
        directory = PAT_ROOT / sub
        if not directory.is_dir():
            continue
        bucket = sets.setdefault(category, [])
        for txt in sorted(directory.rglob("*.txt")):
            try:
                for line in txt.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    bucket.append((line, "PayloadsAllTheThings"))
            except OSError:
                continue
    # 每类封顶 (Directory Traversal 单文件 2 万行, 不封顶会压垮其余类别)
    return {cat: items[:PAT_CAP] for cat, items in sets.items()}


def build_attacks(cap: int, only_source: str = "") -> tuple[list[Attack], dict]:
    attacks: list[Attack] = []
    counts: dict[str, int] = {}
    by_source: dict[str, int] = {}
    oversize = 0
    for category, items in sorted(load_payload_sets().items()):
        for text, source in items:
            if only_source and source != only_source:
                continue
            blob = _b(text)
            if not text or len(blob) > cap:
                oversize += 1
                continue
            counts[category] = counts.get(category, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1
            enc = quote(text, safe="")
            attacks.append(Attack(_raw("GET", f"/search?q={enc}&page=1"),
                                  category, "query", source))
            attacks.append(Attack(
                _raw("POST", "/api/search", body=_b(f"query={enc}&limit=10")),
                category, "form", source))
            if "\r" not in text and "\n" not in text:
                attacks.append(Attack(
                    _raw("POST", "/api/data",
                         headers={"Content-Type": "text/plain"}, body=blob),
                    category, "body-raw", source))
    return attacks, {"categories": counts, "by_source": by_source,
                     "skipped_oversize": oversize}


def load_benign() -> tuple[list[bytes], int]:
    raws: list[bytes] = []
    fp_file = PAYLOAD_ROOT / "false-pos" / "texts.yml"
    texts: list[str] = tolerant_load(fp_file)[0] if fp_file.exists() else []
    for t in texts:
        enc = quote(t, safe="")
        raws.append(_raw("GET", f"/search?q={enc}"))
        raws.append(_raw("POST", "/api/search", body=_b(f"query={enc}")))
    raws.extend(s.raw for s in build_corpus() if not s.expect_block)
    return raws, len(texts)


# ── 引擎评测 ────────────────────────────────────────────────────────────
def run_engine(name: str, attacks: list[Attack], benign: list[bytes],
               paranoia: int, threshold: int) -> dict:
    cfg = Config()
    cfg.waf.mode = "block"
    cfg.waf.paranoia_level = paranoia
    cfg.waf.anomaly_threshold = threshold
    driver = ENGINE_CLASSES[name](cfg)
    try:
        driver.start()
    except Exception:                              # noqa: BLE001
        pass

    def inspect(raw: bytes) -> tuple[bool, float]:
        req = parse_request(raw, "203.0.113.9", 40000)
        t0 = time.perf_counter()
        decision = driver.inspect(req)
        return bool(decision.blocked), (time.perf_counter() - t0) * 1000.0

    for a in attacks[:32]:                          # 预热
        inspect(a.raw)

    by_cat: dict[str, dict[str, int]] = {}
    by_src: dict[str, dict[str, int]] = {}
    lat: list[float] = []
    for a in attacks:
        blocked, ms = inspect(a.raw)
        lat.append(ms)
        b = by_cat.setdefault(a.category, {"total": 0, "blocked": 0})
        b["total"] += 1
        b["blocked"] += int(blocked)
        s = by_src.setdefault(a.source, {"total": 0, "blocked": 0})
        s["total"] += 1
        s["blocked"] += int(blocked)
    for b in by_cat.values():
        b["rate"] = round(b["blocked"] / b["total"], 4) if b["total"] else 0.0
    for s in by_src.values():
        s["rate"] = round(s["blocked"] / s["total"], 4) if s["total"] else 0.0

    fp = sum(int(inspect(raw)[0]) for raw in benign)

    tp = sum(b["blocked"] for b in by_cat.values())
    fn = sum(b["total"] - b["blocked"] for b in by_cat.values())
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    ordered = sorted(lat)

    def pct(p: float) -> float:
        if not ordered:
            return 0.0
        return round(ordered[min(len(ordered) - 1,
                                 max(0, int(len(ordered) * p) - 1))], 3)

    try:
        driver.stop()
    except Exception:                              # noqa: BLE001
        pass
    return {
        "engine": name, "paranoia_level": paranoia,
        "anomaly_threshold": threshold, "rules": driver.rule_count(),
        "attacks": tp + fn, "blocked": tp, "bypassed": fn,
        "recall": round(recall, 4),
        "benign": len(benign), "false_positives": fp,
        "false_positive_rate": round(fp / len(benign), 4) if benign else 0.0,
        "precision": round(precision, 4), "f1": round(f1, 4),
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1]["total"])),
        "by_source": dict(sorted(by_src.items(), key=lambda kv: -kv[1]["total"])),
        "latency_ms": {"mean": round(statistics.fmean(lat), 4) if lat else 0.0,
                       "p50": pct(0.50), "p90": pct(0.90), "p99": pct(0.99),
                       "max": round(max(lat), 3) if lat else 0.0},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/opencode/results/waf.json")
    ap.add_argument("--paranoia", type=int, default=1)
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--engines", default="modsecurity,naxsi,python")
    ap.add_argument("--source", default="", help="只保留某一来源的载荷")
    ns = ap.parse_args()

    print("[*] 装载攻击载荷 ...", flush=True)
    attacks, meta = build_attacks(MAX_PAYLOAD, ns.source)
    benign, fp_texts = load_benign()
    print(f"    攻击请求 {len(attacks)} 条 / 类别 {len(meta['categories'])} 个")
    print(f"    良性请求 {len(benign)} 条 (gotestwaf false-pos {fp_texts} + 项目语料)")
    print(f"    跳过超大载荷 {meta['skipped_oversize']} 条")

    results = {}
    for name in [e.strip() for e in ns.engines.split(",") if e.strip()]:
        print(f"[*] 引擎 {name} (PL{ns.paranoia} threshold={ns.threshold}) ...", flush=True)
        t0 = time.perf_counter()
        results[name] = run_engine(name, attacks, benign, ns.paranoia, ns.threshold)
        r = results[name]
        print(f"    拦截 {r['blocked']}/{r['attacks']} 召回 {r['recall']:.3f} "
              f"误报 {r['false_positives']} 用时 {time.perf_counter() - t0:.1f}s",
              flush=True)

    Path(ns.out).parent.mkdir(parents=True, exist_ok=True)
    Path(ns.out).write_text(json.dumps(
        {"meta": meta, "engines": results, "benign_total": len(benign)},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON -> {ns.out}")

    print("\n===== 汇总 =====")
    print(f"{'engine':12} {'召回':>7} {'精确':>7} {'F1':>7} {'误报率':>8} "
          f"{'P50ms':>8} {'规则':>6}")
    for name, r in results.items():
        print(f"{name:12} {r['recall']:>7.3f} {r['precision']:>7.3f} {r['f1']:>7.3f} "
              f"{r['false_positive_rate']:>8.3f} {r['latency_ms']['p50']:>8.3f} "
              f"{r['rules']:>6}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
