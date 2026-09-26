# sentinel/vendor — 第三方资产 (自包含)

> 本目录由 `python tools/vendor.py` 生成, **请勿手工修改**。
> 逐文件 SHA-256 见 `MANIFEST.json`; `python tools/vendor.py --check` 校验。

Sentinel 的运行时不读取任何同级工程目录: 规则、模板、映射表全部在此。

| 集合 | 上游 | 许可证 | 文件 | 体积 |
| --- | --- | --- | ---: | ---: |
| `crs` | https://github.com/coreruleset/coreruleset | Apache-2.0 | 52 | 0.9 MiB |
| `naxsi` | https://github.com/nbs-system/naxsi | GPL-3.0 | 2 | 0.0 MiB |
| `modsecurity` | https://github.com/owasp-modsecurity/ModSecurity | Apache-2.0 | 1 | 0.1 MiB |
| `nuclei-templates` | https://github.com/projectdiscovery/nuclei-templates | MIT | 11656 | 34.3 MiB |

合计 **11711** 个文件 / **35.3 MiB**。

## 各集合说明

### `crs` — OWASP Core Rule Set

- 上游: https://github.com/coreruleset/coreruleset
- 许可证: Apache-2.0
- 用途: Sentinel 原生 SecRule 解释器直接执行 rules/*.conf; *.data 供 @pmFromFile 使用。

### `naxsi` — Naxsi core rules

- 上游: https://github.com/nbs-system/naxsi
- 许可证: GPL-3.0
- 用途: Sentinel 原生评分器把 MainRule/CheckRule 编译为内部规则。

### `modsecurity` — ModSecurity unicode mapping

- 上游: https://github.com/owasp-modsecurity/ModSecurity
- 许可证: Apache-2.0
- 用途: t:urlDecodeUni / t:utf8toUnicode 的全宽映射表。

### `nuclei-templates` — ProjectDiscovery nuclei templates

- 上游: https://github.com/projectdiscovery/nuclei-templates
- 许可证: MIT
- 用途: Sentinel 原生模板引擎 (sentinel.scanner.templating) 解释这些 YAML。

