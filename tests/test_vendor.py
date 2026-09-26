"""内置第三方资产 (``sentinel/vendor``) 的完整性与装载测试.

「Sentinel 不再依赖同级工程」这件事必须由测试守住: 一旦有人把路径写回
``../waf_pro``, 或者忘了同步某个集合, 引擎会在别人的机器上静默失效。
"""
from __future__ import annotations

import json

import pytest

from sentinel import vendor


class TestManifest:
    def test_manifest_is_readable_and_complete(self):
        data = vendor.manifest()
        assert data["collections"], "MANIFEST.json 为空 —— 请运行 tools/vendor.py"
        assert data["totals"]["files"] > 0

    def test_every_collection_exists_on_disk(self):
        assert vendor.missing() == [], (
            "vendor 集合缺失, 请运行 tools/vendor.py 重新同步")

    def test_manifest_matches_disk(self):
        """清单里的每个文件都应存在且大小一致 (不重算全部哈希, 太慢)."""
        root = vendor.vendor_root()
        problems: list[str] = []
        for collection in vendor.manifest()["collections"]:
            target = root / collection["target"]
            for rel, size, _digest in collection["files"]:
                path = target / rel
                if not path.exists():
                    problems.append(f"缺失 {collection['target']}/{rel}")
                elif path.stat().st_size != size:
                    problems.append(f"大小不符 {collection['target']}/{rel}")
        assert not problems, problems[:10]

    def test_manifest_has_license_and_upstream_for_every_collection(self):
        for collection in vendor.manifest()["collections"]:
            assert collection["upstream"].startswith("https://")
            assert collection["license"]
            assert collection["file_count"] == len(collection["files"])


class TestPaths:
    def test_crs_rules_present(self):
        rules = sorted(vendor.crs_rules_dir().glob("REQUEST-*.conf"))
        assert len(rules) >= 15
        assert vendor.crs_setup_conf().exists()
        # 规则引用的词表 (.data) 必须一起在, 否则 @pmFromFile 会全空
        assert (vendor.crs_rules_dir() / "sql-errors.data").exists()
        assert (vendor.crs_rules_dir() / "scanners-user-agents.data").exists()

    def test_naxsi_core_rules_present(self):
        path = vendor.naxsi_core_rules()
        assert path.exists()
        text = path.read_text(encoding="utf-8")
        assert text.count("MainRule") >= 40

    def test_unicode_mapping_present(self):
        path = vendor.unicode_mapping()
        assert path.exists() and path.stat().st_size > 10_000

    def test_nuclei_templates_present(self):
        root = vendor.nuclei_templates_dir()
        assert root.exists()
        assert (root / "http").is_dir()
        assert len(list((root / "http").rglob("*.yaml"))) > 1000

    def test_no_runtime_path_points_at_sibling_projects(self):
        """运行时代码里不得再出现 ../waf_pro 或 ../digger_pro."""
        from pathlib import Path
        sentinel_pkg = Path(vendor.__file__).resolve().parents[1]
        offenders: list[str] = []
        for path in sentinel_pkg.rglob("*.py"):
            if "vendor" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for needle in ("waf_pro", "digger_pro"):
                if needle in text:
                    offenders.append(f"{path.relative_to(sentinel_pkg)}: {needle}")
        assert not offenders, offenders


class TestSummary:
    def test_summary_reports_totals(self):
        summary = vendor.summary()
        assert summary["totals"]["collections"] >= 4
        keys = {item["key"] for item in summary["collections"]}
        assert {"crs", "naxsi", "nuclei-templates"} <= keys

    def test_summary_is_json_serialisable(self):
        json.dumps(vendor.summary())


@pytest.mark.integration
class TestEnginesUseVendorData:
    def test_crs_engine_loads_from_vendor(self):
        from sentinel.core.config import Config
        from sentinel.waf.engines.modsecurity import ModSecurityEngine
        driver = ModSecurityEngine(Config())
        assert driver.engine is not None
        assert driver.rule_count() > 300
        sources = " ".join(driver.engine.ruleset.sources)
        assert "vendor" in sources, sources

    def test_naxsi_engine_loads_from_vendor(self):
        from sentinel.core.config import Config
        from sentinel.waf.engines.naxsi import NaxsiEngine
        driver = NaxsiEngine(Config())
        assert driver.engine is not None
        assert driver.rule_count() >= 40
