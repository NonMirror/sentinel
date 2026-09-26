# Sentinel · 可视化安全运营与管理平台

> 轻量级防火墙 + 漏洞扫描子系统 + 极致 Vim 键位 TUI
> —— **引擎、规则语言解释器、模板解释器都是本仓自己的代码**。

Sentinel 不调用任何外部安全二进制。它自己解释 ModSecurity 的规则语言并执行
真实的 OWASP CRS 规则、自己实现 Naxsi 的评分模型、自己解释 nuclei 的 YAML
模板、自己实现主动扫描插件。第三方**数据**（规则、模板、映射表）由
`tools/vendor.py` 一次性收敛进 `sentinel/vendor/`，运行时不再读取任何同级目录。

```
                    ┌──────────────────────────────────────────────┐
                    │  综设 III  可视化安全运营与管理平台 (TUI)      │
                    │  sentinel.tui  ·  Textual + Catppuccin Frappé │
                    └───────────────┬──────────────────────────────┘
              ┌─────────────────────┴──────────────────────┐
              ▼                                            ▼
 ┌────────────────────────────┐             ┌──────────────────────────────┐
 │ 综设 II  轻量级防火墙       │             │ 综设 I  漏洞扫描子系统        │
 │ sentinel.waf               │             │ sentinel.scanner             │
 │  解析 → 归一化 → 规则 → 阻断│             │  目标识别 → 检测 → 漏洞库 → 报告│
 │  ▸ SecRule 解释器 (自研)   │             │  ▸ 模板解释器 (自研)          │
 │  ▸ Naxsi 评分器  (自研)    │             │  ▸ 插件式主动扫描 (自研)      │
 │  ▸ 内置轻量规则集          │             │  ▸ 内置检测器 (10 类)         │
 └────────────┬───────────────┘             └───────────────┬──────────────┘
              └──────────────────┬───────────────────────────┘
                                 ▼
                 ┌────────────────────────────────┐
                 │ 后端 WEB 漏洞靶场  sentinel.lab │
                 │ 多实例 · 预置 SQLi/XSS/SSRF/... │
                 └────────────────────────────────┘
```

## 目录

- [设计要点：从「调用」到「实现」](#设计要点从调用到实现)
- [架构映射](#架构映射)
- [内置第三方资产](#内置第三方资产)
- [快速开始](#快速开始)
- [TUI 界面](#tui-界面)
- [键位与命令](#键位与命令)
- [测试与评测](#测试与评测)
- [项目结构](#项目结构)

## 设计要点：从「调用」到「实现」

早期版本把 `nginx + libmodsecurity`、`nuclei` 二进制当成黑盒「驱动」：Sentinel
生成配置、托管进程、回采日志。它能跑，但**能力上限就是上游的能力上限**，
而且一旦同级目录改名、换台机器、缺一个 Go 二进制，整个平台就静默失效。

现在这些能力都由本仓实现。三处最关键的改造：

### 1. ModSecurity 规则语言解释器（`sentinel/waf/secrule/`）

自己解析 `SecRule` / `SecAction` / `SecDefaultAction` / `SecMarker`，自己实现
变量空间（`ARGS` / `REQUEST_HEADERS` / `TX` / …）、算子（`@rx` / `@pmFromFile` /
`@detectSQLi` / `@ge` / …）、变换（`t:urlDecodeUni` / `t:cmdLine` / …）与动作
（`setvar` / `ctl` / `chain` / `skipAfter` / `capture`）。然后**直接加载
`sentinel/vendor/crs` 里的真实 OWASP CRS 规则**：

```python
from sentinel.core.config import Config
from sentinel.waf.engines import ModSecurityEngine

driver = ModSecurityEngine(Config())      # 装载 457 条请求侧 CRS 规则 (phase 1/2)
decision = driver.inspect(request)        # -> Decision(verdict/score/matched_rules)
```

ModSecurity 的规则语言有一批**反直觉且静默失效**的语义，实现时逐条对齐并用
测试固化（详见 `tests/test_secrule.py` 与 `sentinel/waf/secrule/syntax.py`）：

| 语义 | 直觉写法 | 实际语义 |
| --- | --- | --- |
| `@validateByteRange` / `@validateUtf8Encoding` / `@validateUrlEncoding` | 合法则命中 | **校验失败才命中** |
| `&TX:x` | 取变量值 | 取**命中个数**（未定义时是 0） |
| `A\|!A:x` | 对 A:x 取反 | 从已累积集合中**剔除** A:x |
| `SecDefaultAction "…,pass"` 下的 `block` | 拦截 | **只计分**，拦截由 `REQUEST-949` 的 `deny` 完成 |
| Paranoia Level | 过滤规则集 | `skipAfter` + `SecMarker` **分级跳转** |
| `TX` 键名大小写 | 区分 | **不区分**（CRS 写 `tx.` 读 `TX.`） |

同时补齐了 PCRE 与 Python `re` 的方言差异（`\x{bf}`、`(?|…)`、`[\--9]`、
模式中部的 `(?i)`），并把这些改写**限制在 Python 编译失败时才启用** ——
不会影响本来就正确的规则。引擎健康状态里会如实报告改写条数：

```
解释器自检   正则: 编译失败 0 / PCRE 方言改写 10
```

### 2. Naxsi 评分器（`sentinel/waf/naxsi/`）

Naxsi 的模型与 ModSecurity 完全不同，因此单独实现：解析 `MainRule` 的
`mz:`（检测面）与 `s:$SQL:4`（分区计分），按 `CheckRule` 的阈值判定。
46 条核心规则 + 6 个计分项，PL1–PL4 逐级收紧阈值。

### 3. nuclei 模板解释器（`sentinel/scanner/templating/`）

自己解析 nuclei 的 YAML 模板并执行：`method` / `path` / `raw` / `headers` /
`body` / `payloads` / `attack`（sniper·pitchfork·clusterbomb·batteringram）、
matchers（status·size·word·regex·binary·dsl）、extractors（regex·kval·json·dsl）、
`{{...}}` 插值与 DSL 函数。模板数据是官方 `nuclei-templates`（11,309 条 HTTP
模板已入仓）。

DSL 用 `ast` 白名单求值而不是 `eval` —— 模板来自第三方仓库，直接执行等于把
任意代码执行权交出去（`tests/test_templating.py` 里有对应的拒绝用例）。

**只扫本次目标**：官方模板里有一批把外部主机写死在 `path` 里的 SSRF/OAST 探测
（`169.254.169.254`、`*.oast.pro`、`generativelanguage.googleapis.com` …）。默认
只允许请求本次扫描的目标主机，其余跳过并计数（模板面板可见 `blocked_external`）——
既避免扫描器悄悄联系第三方，也消除了每次 5 秒的超时（实测同一轮扫描
**87 s → 1.5 s**）。需要时用 `NucleiEngine(allow_external=True)` 打开。

## 架构映射

| 架构层 | 子系统 | 代码包 | 职责 |
| --- | --- | --- | --- |
| 综设 I | 漏洞扫描子系统 | `sentinel/scanner/` | 目标识别 → 漏洞检测 → 漏洞库/规则引擎 → 报告生成 |
| 综设 II | 轻量级防火墙 | `sentinel/waf/` | HTTP 解析 → 变换归一化 → 特征/规则 → 阻断与审计 |
| 综设 III | 可视化安全运营与管理平台 | `sentinel/tui/` | 仪表盘/配置/入侵检测/规则/审计/引擎与资产 |
| 后端 | WEB 漏洞靶场 | `sentinel/lab/` | 多实例靶场，预置十类漏洞供扫描与拦截验证 |

## 内置第三方资产

第三方**数据**（不是代码）由 `tools/vendor.py` 从上游一次性收敛进
`sentinel/vendor/`，逐文件记录 SHA-256 与许可证：

| 集合 | 上游 | 许可证 | 规模 | 用途 |
| --- | --- | --- | ---: | --- |
| `crs/` | coreruleset/coreruleset | Apache-2.0 | 52 文件 | OWASP CRS 规则与词表 |
| `naxsi/` | nbs-system/naxsi | GPL-3.0 | 2 文件 | `naxsi_core.rules` |
| `modsecurity/` | owasp-modsecurity/ModSecurity | Apache-2.0 | 1 文件 | `unicode.mapping` |
| `nuclei-templates/` | projectdiscovery/nuclei-templates | MIT | 11,656 文件 | HTTP 模板与词表 |

```bash
python tools/vendor.py            # 从上游重新同步
python tools/vendor.py --check    # 校验清单与磁盘一致 (CI 用)
```

`tests/test_vendor.py` 会守住这条边界：**运行时代码里不得再出现 `waf_pro` /
`digger_pro` 路径**。

## 快速开始

只需 `mise` 与 `uv`，**不需要 C 工具链、不需要 Go**：

```bash
cd ~/Projects/sentinel
mise install            # 安装工具链 (Python 3.14 + uv)
mise run install        # uv sync --extra test --extra report
mise run test           # 全部单元 + 集成 + 端到端测试
mise run tui            # 启动 TUI 管理平台
```

WAF 与扫描器开箱即用：规则与模板已在 `sentinel/vendor/` 中。

**可选**：构建真实的 nginx + ModSecurity / Naxsi 数据面，作为**参考实现**用于
校对原生解释器的语义（不构建也不影响任何功能）：

```bash
mise run build:engines  # tools/build_engines.sh -> sentinel/build/
```

常用任务：

| 任务 | 说明 |
| --- | --- |
| `mise run test` | 全部测试 |
| `mise run test:fast` | 仅快速单元测试（跳过 `slow`） |
| `mise run junit` | 运行测试并输出 `reports/junit.xml` |
| `mise run bench` | 采集性能与质量基准 → `reports/bench-*.json` / `.md` |
| `mise run report` | 基准 + 生成中文综合报告（MD/HTML/DOCX） |
| `mise run shot` | 重新生成 `docs/tui/*.png` 截图 |
| `mise run lab` | 启动靶场 + WAF 反向代理（无 TUI） |
| `mise run lint` | 语法与导入自检 |
| `mise run vendor` | 重新同步 `sentinel/vendor/` |

## TUI 界面

全部界面使用 **Catppuccin Frappé** 配色（`#303446` base / `#8caaee` accent，
与 `catppuccin-frappe.theme` 一致）。截图见 `docs/tui/`。

| 模块 | 名称 | 综设 |
| --- | --- | --- |
| `1` | WAF 可视化（实时 QPS / 拦截率 / 命中规则 TOP / 延迟分位） | 综设 III |
| `2` | 配置管理（监听、模式、阈值、PL、负载均衡策略） | 综设 III |
| `3` | 入侵检测管理（逐条判定、命中规则、来源画像） | 综设 II |
| `4` | 规则防御管理（规则启停、导出 ModSecurity / Naxsi 语法） | 综设 II |
| `5` | 日志审计管理（结构化审计流、`dd` 冻结视图） | 综设 II |
| `6` | 漏洞检测（单引擎 / 多引擎融合扫描） | 综设 I |
| `7` | 漏洞库管理（插件与 OWASP/CWE 映射） | 综设 I |
| `8` | 报告生成（Markdown / HTML / JSON） | 综设 I |
| `9` | 引擎与资产（原生解释器 · 内置规则/模板 · 可选 C 数据面） | 综设 II |

侧栏带实时徽标（拦截数 / 告警数 / 漏洞数 / 规则数），可直接鼠标点击切换；
模块 9 会同时展示**内置资产的来源与许可证**和**解释器自检结果**（正则编译
失败数、方言改写数）。

## 键位与命令

Vim 风格操作：

| 键 | 作用 | 键 | 作用 |
| --- | --- | --- | --- |
| `1`–`9` | 切换模块 | `j` / `k` | 下 / 上移动 |
| `gg` / `G` | 首行 / 末行 | `h` / `l` | 焦点左 / 右 |
|  |  |  | *`j`/`k` 作用于当前面板：有数据的表格移动光标，否则滚动实时日志；日志里按 `k` 暂停自动跟随，`G` 回到末行并恢复跟随。面板没有可移动对象时状态栏会说明原因。* |
| `Enter` | 激活 / 切换引擎 | `x` / `Space` | 启停规则 / 切换引擎 |
| `dd` | 清空 / 冻结当前视图 | `yy` | 复制当前行 |
| `/` | 搜索过滤 | `:` | 命令模式 |
| `r` | 刷新 / 重载 | `s` / `D` | 普通 / 深度扫描 |
| `a` / `A` | 多引擎融合 / 深度融合扫描 | `Tab` | 下一模块 |
| `?` | 帮助浮层 | `q` | 退出 |

命令模式：

```
:w                              保存配置到 sentinel.toml
:set mode=block|detect|off      :set threshold=3..30   :set pl=1..4
:set rate=0..200                :set strategy=round_robin|least_conn|random|ip_hash
:engine [name]                  查看 / 热切换引擎
:vendor                         内置资产来源与完整性
:scan [url]  :scan! [url]       扫描 / 深度扫描
:scanall [url]  :scanall! [url] 多引擎融合扫描
:report [md|html|json]  :export 出报告 / 导出当前引擎规则
:reload  :clear
```

引擎清单：

| 引擎 | 类型 | 说明 |
| --- | --- | --- |
| `modsecurity` | 原生（默认） | Sentinel SecRule 解释器 + OWASP CRS |
| `naxsi` | 原生 | Sentinel Naxsi 评分器 + 核心规则 |
| `python` | 原生 | Sentinel 内置轻量规则集 |
| `nginx-modsecurity` | 参考（可选） | 真实 nginx + libmodsecurity，用于语义校对 |
| `nginx-naxsi` | 参考（可选） | 真实 nginx + Naxsi C 模块，同上 |

## 项目结构

```
sentinel/
├── sentinel/
│   ├── waf/            综设 II
│   │   ├── secrule/    ★ ModSecurity 规则语言解释器 (syntax·variables·transforms·operators·engine)
│   │   ├── naxsi/      ★ Naxsi 规则解析与评分器
│   │   ├── engines/    引擎驱动: 原生 (modsecurity·naxsi·python) + 参考 (nginx-*)
│   │   └── ...         解析器 / 变换 / 特征 / 规则 / 反代 / 负载均衡 / IDS
│   ├── scanner/        综设 I
│   │   ├── templating/ ★ nuclei YAML 模板解释器 (model·expression·matchers·runner·engine)
│   │   ├── plugins/    ★ 插件式主动扫描 (设计参考 w13scan)
│   │   └── ...         爬虫 / 检测器 / 漏洞库 / 多引擎融合 / 报告
│   ├── tui/            综设 III
│   ├── lab/            后端靶场（多实例）
│   ├── core/           配置 / 事件总线 / 指标 / 审计 / 数据模型
│   ├── vendor/         内置第三方资产 (由 tools/vendor.py 生成)
│   └── reporting.py    中文综合测试报告（MD / 自包含 HTML / DOCX）
├── benchmarks/         语料库 + 综合基准（质量 / 吞吐 / QPS / 权衡曲线）
├── tools/              vendor.py · build_engines.sh · capture_tui.py
├── templates/nuclei/   自研靶场 POC 模板
├── tests/              单元 / 集成 / 端到端测试
└── docs/tui/           TUI 截图（PNG + SVG）
```

## 测试与评测

- **测试**：`mise run test` —— **587 项全部通过**（0 失败；未构建参考数据面时
  9 项真实 nginx 用例自动跳过），明细见 `reports/junit.xml` 与综合报告的
  「测试用例矩阵」。其中解释器部分（`tests/test_secrule.py` /
  `test_naxsi.py` / `test_templating.py`）大半是开发期踩过的坑的固化，
  例如「`@validateByteRange` 命中于校验失败」「`&TX:x` 取的是个数」。
- **语料**：`benchmarks/corpus.py` 构造 **178** 条合法 HTTP/1.1 原始报文
  （75 正常 + 103 攻击：SQLi / XSS / RCE / LFI / SSRF / 扫描器 / 协议 / 侦察）。
  正常样本刻意包含「看起来像攻击」的良性输入（`select the best laptop`、
  `union station opening hours`），用于检验精确率。
- **质量**：按**原始报文回放**评测（保留方法 / 头部 / 请求体），统计
  TP/FP/TN/FN、精确率、召回率、F1、误报率与逐类检出率。
- **性能**：解析器吞吐、解释器判定吞吐、代理端到端延迟、负载均衡均匀度、
  模板解释器吞吐、规则装载耗时。
- **权衡**：Paranoia Level（PL1–PL4）与异常评分阈值扫描曲线。
- **对照**：真实 `nginx + ModSecurity` 数据面（若已构建）与原生解释器跑
  **同一套 CRS 规则**，用于校对语义一致性。

### 最近一次实测（2026-09-25，Python 3.14.7）

原生引擎按原始报文回放评测 178 条语料：

| 引擎 | 精确率 | 召回率 | F1 | 误报 | 漏报 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `modsecurity`（原生 SecRule 解释器 + OWASP CRS，PL1） | **100.0%** | 89.3% | **94.4%** | 0 | 11 |
| 早期 nginx + libmodsecurity 数据面（对照） | 90.3% | 90.3% | 90.3% | 10 | 10 |

原生解释器**零误报**：语料里 `select the best laptop`、`union station opening
hours`、`order by popularity` 这类良性近似攻击全部放行。逐类检出率：

| 类别 | 检出 | 类别 | 检出 |
| --- | ---: | --- | ---: |
| XSS | 22/22 (100%) | SSRF | 9/10 (90%) |
| LFI | 11/11 (100%) | RCE | 9/11 (82%) |
| SQLi | 27/28 (96%) | 协议 | 1/2 (50%) |
| 扫描器指纹 | 11/12 (92%) | 侦察路径 | 2/7 (29%) |

默认取 **PL1**：Paranoia Level 抬高的代价远大于收益（同一语料，阈值 5）：

| PL | 精确率 | 召回率 | F1 | 误报 | 漏报 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| **1（默认）** | **100.0%** | 89.3% | **94.4%** | **0** | 11 |
| 2 | 95.0% | 92.2% | 93.6% | 5 | 8 |
| 3 | 92.2% | 92.2% | 92.2% | 8 | 8 |
| 4 | 73.3% | 93.2% | 82.1% | 35 | 7 |

「侦察路径」是全 PL 都提不上去的一类（`/phpmyadmin`、`/actuator/env`、`/wp-login.php`）：
CRS 的定位是**请求侧攻击特征**，路径侦察属于资产发现。这类目标由扫描子系统的
内置检测器与插件引擎覆盖（多引擎融合扫描里能看到对应发现），这也是 Sentinel
把 WAF 与扫描器放在同一个平台里的原因。

解释器自身开销约 **2.6 ms/请求**（391 req/s 单线程），规则装载 457 条约 0.2 s；
nginx+ModSecurity 数据面对照为 5.66 ms（P50），量级相当。

> 完整数字随每次 `mise run bench` 重新生成，见 `reports/bench-*.json` 与
> `reports/report-*.html`（自包含，内嵌图表与截图）。

## 免责声明

本项目用于教学与授权范围内的安全测试。请勿对未授权的目标发起扫描或攻击。
内置的第三方规则与模板分别遵循其原始许可证（见 `sentinel/vendor/README.md`）。
