"""配置管理测试: 默认值、校验规则、JSON/TOML/极简 YAML 载入与导出.

覆盖架构图中的 "配置管理" 组件 (综设 III 管理平台)。
"""
from __future__ import annotations

import json

import pytest

from sentinel.core.config import (BackendConfig, Config, LabConfig, ListenerConfig,
                                  ScannerConfig, TuiConfig, WafConfig, load_config)


def test_default_config_is_valid_and_complete():
    cfg = Config()
    assert isinstance(cfg.listener, ListenerConfig)
    assert isinstance(cfg.waf, WafConfig)
    assert isinstance(cfg.scanner, ScannerConfig)
    assert isinstance(cfg.lab, LabConfig)
    assert isinstance(cfg.tui, TuiConfig)
    assert cfg.listener.host == "127.0.0.1" and cfg.listener.port == 8080
    assert cfg.waf.enabled is True and cfg.waf.mode == "block"
    assert 1 <= cfg.waf.paranoia_level <= 4
    assert cfg.waf.strategy == "round_robin"
    assert cfg.lab.instances == 3
    assert cfg.tui.vim_mode is True
    assert [b.name for b in cfg.backends] == ["app-1", "app-2", "app-3"]
    assert [b.port for b in cfg.backends] == [9001, 9002, 9003]
    assert cfg.validate() == []


def test_backend_address_and_weight_defaults():
    backend = BackendConfig(name="app-x", port=9100)
    assert backend.address == "127.0.0.1:9100"
    assert backend.weight == 1
    assert backend.health_path == "/health"


def test_validate_reports_each_problem():
    cfg = Config()
    cfg.waf.mode = "bogus"
    cfg.waf.strategy = "nope"
    cfg.waf.paranoia_level = 9
    cfg.listener.port = 99999
    cfg.backends = [BackendConfig(name="bad", port=0)]
    cfg.scanner.concurrency = 0
    problems = cfg.validate()
    text = " | ".join(problems)
    assert "waf.mode" in text
    assert "waf.strategy" in text
    assert "paranoia_level" in text
    assert "listener.port" in text
    assert "bad" in text
    assert "concurrency" in text
    assert len(problems) == 6


def test_validate_requires_at_least_one_backend():
    cfg = Config()
    cfg.backends = []
    assert any("后端" in problem for problem in cfg.validate())


def test_json_roundtrip(tmp_path):
    cfg = Config()
    cfg.waf.mode = "detect"
    cfg.waf.paranoia_level = 3
    cfg.waf.allow_ips = ["10.0.0.1", "10.0.0.2"]
    cfg.backends = [BackendConfig(name="b1", host="10.0.0.9", port=8081, weight=3)]
    path = tmp_path / "sentinel.json"
    cfg.save(str(path))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["waf"]["mode"] == "detect"
    assert data["waf"]["paranoia_level"] == 3
    assert data["backends"][0]["weight"] == 3

    again = Config.load(str(path))
    assert again.waf.mode == "detect"
    assert again.waf.paranoia_level == 3
    assert again.waf.allow_ips == ["10.0.0.1", "10.0.0.2"]
    assert again.backends[0].address == "10.0.0.9:8081"
    assert again.validate() == []


def test_toml_load(tmp_path):
    path = tmp_path / "sentinel.toml"
    path.write_text(
        "[waf]\n"
        'mode = "detect"\n'
        "paranoia_level = 4\n"
        "anomaly_threshold = 7\n"
        'allow_ips = ["10.0.0.1"]\n'
        "\n[listener]\n"
        "port = 9090\n"
        "\n[lab]\n"
        "instances = 2\n",
        encoding="utf-8",
    )
    cfg = Config.load(str(path))
    assert cfg.waf.mode == "detect"
    assert cfg.waf.paranoia_level == 4
    assert cfg.waf.anomaly_threshold == 7
    assert cfg.waf.allow_ips == ["10.0.0.1"]
    assert cfg.listener.port == 9090
    assert cfg.lab.instances == 2
    assert len(cfg.backends) == 3          # 未指定时回退默认后端


def test_mini_yaml_load_and_scalar_coercion(tmp_path):
    path = tmp_path / "sentinel.yaml"
    path.write_text(
        "waf:\n"
        "  mode: block\n"
        "  paranoia_level: 2\n"
        "  rate_limit_rps: 12.5\n"
        "  inspect_body: false\n"
        "listener:\n"
        "  host: 0.0.0.0\n"
        "  port: 8123\n",
        encoding="utf-8",
    )
    cfg = Config.load(str(path))
    assert cfg.waf.mode == "block"
    assert cfg.waf.paranoia_level == 2
    assert cfg.waf.rate_limit_rps == pytest.approx(12.5)
    assert cfg.waf.inspect_body is False
    assert cfg.listener.host == "0.0.0.0"
    assert cfg.listener.port == 8123


def test_load_missing_file_returns_defaults():
    cfg = Config.load("/nonexistent/sentinel.toml")
    assert cfg.validate() == []
    assert cfg.listener.port == 8080


def test_from_dict_ignores_unknown_keys_and_bad_types(tmp_path):
    cfg = Config.from_dict({"waf": {"mode": "off", "unknown_option": 1},
                            "totally_unknown": True})
    assert cfg.waf.mode == "off"
    assert not hasattr(cfg.waf, "unknown_option")


def test_load_config_accepts_none_and_missing_path():
    assert load_config(None).validate() == []
    assert load_config("/nonexistent/sentinel.toml").validate() == []


def test_load_config_raises_on_invalid_file(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"waf": {"mode": "not-a-mode"}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(path))
