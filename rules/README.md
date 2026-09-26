# Sentinel 规则目录

`rules/` 存放 **Sentinel 平台自身的自定义规则与白名单**, 与内置的 CRS / Naxsi
规则库协同工作。规则语义对齐 **OWASP ModSecurity SecRule** 子集, 因此可以直接
导出为真实引擎 (原生解释器或 nginx + libmodsecurity) 可加载的指令。

## 目录约定

| 文件 | 作用 |
| --- | --- |
| `custom-example.json` | 自定义规则示例 (启用后与内置规则合并, 同 ID 覆盖内置) |
| `*.json` 中的 `rules[].naxsi_whitelist` | 导出为 Naxsi `BasicRule wl:` 白名单 |

## 数据格式

```json
{
  "rules": [
    {
      "id": 999001,
      "description": "拦截对 /admin 的扫描探测",
      "variables": ["URI"],
      "operator": "contains",
      "operator_arg": "/admin",
      "severity": "medium",
      "action": "block",
      "category": "recon"
    }
  ]
}
```

`naxsi_whitelist` 字段用于向 Naxsi 引擎注册白名单 (避免误杀), 例如:

```json
{ "rules": [ { "id": 999100, "description": "登录接口放行", "naxsi_whitelist": "999100" } ] }
```

## 与引擎的关系

| 引擎 | 规则来源 | Sentinel 的角色 |
| --- | --- | --- |
| `modsecurity` | `sentinel/vendor/crs/rules/*.conf` (OWASP CRS) | **自己解释 SecRule 语言并执行**, 按 PL 与阈值运行 |
| `naxsi` | `sentinel/vendor/naxsi/naxsi_config/naxsi_core.rules` | **自己实现评分模型**, 按 PL 收紧阈值 |
| `python` | `rules/*.json` + 内置规则 | 内置轻量规则引擎 |
| `nginx-*` (可选) | 同上 (同一份数据) | 生成 nginx 配置并托管真实 C 数据面, 用于语义校对 |

规则数据由 `tools/vendor.py` 收敛进 `sentinel/vendor/`; 运行时不读取任何同级目录。

## 导出

在 TUI 中执行 `:export`, 或在 Python 中:

```python
from sentinel.runtime import SentinelRuntime
runtime = SentinelRuntime(engine="modsecurity").start()
n = runtime.export_rules("reports/exported-modsecurity-crs-rules.conf")
print(n, "条规则已导出")
runtime.stop()
```
