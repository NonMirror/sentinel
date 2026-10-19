# benchmarks/scripts —— 2026-10-18 WAF & 扫描器基准复现脚本

配套报告：[`../bench-20261018-waf-scanner.md`](../bench-20261018-waf-scanner.md)
原始数据：[`../data/20261018/`](../data/20261018/)

## 脚本

| 脚本 | 用途 |
|---|---|
| `bench_waf_acceptance.py` | 完全离线：固定434正向＋169良性，对比standard／balanced；同时检查请求加权与类别等权召回，保留失败历史 |
| `bench_csic_benign.py` | 完全离线：固定摘要的CSIC正常请求；按原始报文SHA-256排序抽样，支持不重叠留出区间，不测攻击召回 |
| `bench_frameworks.py` / `framework_apps.py` | 仅本机回环：Django、Flask、FastAPI 的普通请求解析、代理转发与被动响应头检查；独立临时依赖环境 |
| `bench_waf_policy.py` | 完全离线：同一 GoTestWAF/良性语料比较 CRS 检测与拦截等级，保留逐条良性命中规则 |
| `bench_waf.py` | WAF 进程内评测：分类拦截率 / 召回 / 误报 / F1 / 决策延迟。三引擎 × PL 扫描 |
| `bench_waf_proxy.py` | WAF 端到端代理形态：向 Sentinel 或 `--endpoint` 指定的竞品前端回放固定原始报文，统计状态、类别召回、误报与延迟 |
| `bench_lab.py` | 扫描器：对项目自带靶场做多引擎（nuclei/w13scan/builtin）融合扫描，对齐 11 类漏洞 |
| `bench_multi.py` | 扫描器：把已知漏洞端点直接喂给三引擎，统计各引擎与融合发现 |
| `bench_detectors.py` | 扫描器：检测器级（跳过爬虫）——给 (端点, 参数, 位置)，看检测器能否命中 |
| `bench_regressions.py` | 完全离线：22 项 WAF/爬虫/报告语义检查，参数规模微基准，三引擎质量矩阵；默认每档重复 3 次 |
| `bench_crs_fixtures.py` | 完全离线：适配公开 CRS/go-ftw REQUEST YAML，逐条核对期望/不期望的规则 ID，列出不支持项 |
| `bench_passive_public.py` | 完全离线：适配 ZAP 两个被动规则测试类的响应样本，检查三种应用页面快照的元数据和访问边界 |
| `bench_modsecurity_units.py` | 完全离线：适配 ModSecurity 官方算子/转换函数 fixtures，保留失败和不支持项，报告按操作等权的平均通过率 |
| `bench_observatory.py` | 完全离线：适配 MDN HTTP Observatory 五种响应头的 52 项断言，另列 2 项未支持的 HTML meta 子用例 |
| `bench_wpt_headers.py` | 完全离线：WPT 的15项 nosniff 生效语义与7项 CORP 无效值断言；格式告警与保护生效分别记录 |
| `bench_structured_headers.py` | 完全离线：适配 HTTPWG 结构化字段 Item 语法及主 token 检查；不是漏洞检出率 |
| `bench_naxsi_fixtures.py` | 完全离线：读取 Naxsi 上游 Test::Nginx 静态请求用例，比较允许/拦截，列出 Perl eval、配置和协议等未支持项 |
| `bench_proxy_benign.py` | 仅本机回环：6 种普通请求经过真实代理，验证请求目标和正文完整转发，并测量延迟；含直连基线 |

## 离线回归与扩展基准

```bash
# 项目自带语料，不依赖靶场或外部载荷
.venv/bin/python benchmarks/scripts/bench_regressions.py \
  --out benchmarks/data/20261018/regressions-project-after.json

# GoTestWAF 434 条攻击样本 + 169 条良性样本；缺失外部语料时明确失败
.venv/bin/python benchmarks/scripts/bench_regressions.py --external \
  --out benchmarks/data/20261018/regressions-after.json
```

该脚本不发送网络请求，爬虫和扫描引擎使用内存响应与替身。输出包含语料 SHA-256、
环境信息、逐次质量指标、语义检查结果以及 10/100/500 参数解析中位耗时。
语义用例是针对已定位缺陷的回归检查，不代表通用漏洞检出率。
`regressions-before.json` 为本轮修改前的历史快照，复测应另存文件，避免覆盖基线。

## Django、Flask、FastAPI 普通请求集成

```bash
uv venv /tmp/sentinel-framework-replay --python .venv/bin/python
uv pip install --python /tmp/sentinel-framework-replay/bin/python \
  -r benchmarks/data/20261018/framework-requirements-round6.txt
.venv/bin/python benchmarks/scripts/bench_frameworks.py \
  --framework-python /tmp/sentinel-framework-replay/bin/python --repeats 3 \
  --out /tmp/sentinel-framework-replay.json
```

框架仅安装在独立环境；项目依赖不变。子进程只绑定 `127.0.0.1` 的随机端口，测试结束自动退出。
每个框架使用 10 种普通请求，比较直连与 5 个代理配置，各重复 3 次，共 540 次计量请求。
启动探活和建立直连期望值的请求不计入该分母。所有直连结果必须先通过固定内容断言，才能作为代理对照。
检查请求方法、解码路径、重复参数、JSON、表单、上传文件哈希及 5 类响应头。

响应头测试包含默认、有效、无效三种配置：3 个框架共 9 种场景，6 条访问路径 × 3 次重复后为 162 项检查。
代理拦截、正文损坏、连接失败均不能计为被动检查通过，也不能虚算成扫描器漏报。
Django 启用 `SecurityMiddleware`；Flask 经 `WsgiToAsgi`；三者统一由 uvicorn 提供 HTTP 服务。
因此结果是这些具体应用和部署方式的集成证据，并非全部默认部署的保证。

这是 **1 个自建集成套件覆盖 3 个公开 Web 框架**，不是 3 个第三方漏洞 benchmark。
不发送攻击请求，不测试认证、数据库、TLS、浏览器行为或漏洞覆盖率，也不用于吞吐排名。
`frameworks-round6-before.json` 保留修复前结果；`frameworks-round6-after.json` 为同一语料修复后结果。

## 公开 CRS / ZAP 固定版本复现

```bash
git init /tmp/sentinel-crs-replay
git -C /tmp/sentinel-crs-replay remote add origin https://github.com/coreruleset/coreruleset.git
git -C /tmp/sentinel-crs-replay fetch --depth 1 origin 30cb436b261a9f5ec32a5a0677e17f3cfa1a8739
git -C /tmp/sentinel-crs-replay checkout --detach FETCH_HEAD

git init /tmp/sentinel-zap-replay
git -C /tmp/sentinel-zap-replay remote add origin https://github.com/zaproxy/zap-extensions.git
git -C /tmp/sentinel-zap-replay fetch --depth 1 origin 15fc3d10ae9358ae72b57caba79009e3efca69eb
git -C /tmp/sentinel-zap-replay checkout --detach FETCH_HEAD

.venv/bin/python benchmarks/scripts/bench_crs_fixtures.py \
  --crs-root /tmp/sentinel-crs-replay --out /tmp/sentinel-crs-replay.json
.venv/bin/python benchmarks/scripts/bench_passive_public.py \
  --zap-root /tmp/sentinel-zap-replay \
  --pages benchmarks/data/20261018/public-app-pages.json \
  --out /tmp/sentinel-passive-replay.json
```

CRS 适配器仅支持单阶段、结构化请求和数字规则 ID 断言；排除项在结果中逐条列出，
不是通过项。负向断言仅表示特定规则不应匹配，不能转换成全局良性误报率。
当前使用固定 commit 对齐后的 CRS 规则运行 PL4/detect；早期快照的规则版本曾不一致，详见报告 §9。
`crs-fixtures-before.json` 是 JSON/XML 修复前，`crs-fixtures-json.json` 是仅 JSON 修复后，
`crs-fixtures-after.json` 是两项修复后的结果。

ZAP 适配器读取两个测试类中的 12 个内容断言，未运行 ZAP 二进制及全部测试。
Sentinel 对普通错误页面仅给出 INFO；不将其计为已确认漏洞，也不比较 ZAP 告警等级。
三种页面来自本机 Juice Shop、DVWA、WebGoat 的普通 GET，镜像标识和采样路径见
[`public-app-metadata.json`](../data/20261018/public-app-metadata.json)。复现使用保存的快照，
不需要登录、启动容器或访问外部目标，也不代表完整应用漏洞覆盖。

## ModSecurity 官方语义套件

```bash
git init /tmp/sentinel-modsecurity-replay
git -C /tmp/sentinel-modsecurity-replay remote add origin https://github.com/owasp-modsecurity/ModSecurity.git
git -C /tmp/sentinel-modsecurity-replay fetch --depth 1 origin 84b599623ebea596c72ddda9809298fc601d6f4f
git -C /tmp/sentinel-modsecurity-replay checkout --detach FETCH_HEAD
git -C /tmp/sentinel-modsecurity-replay submodule update --init --depth 1 test/test-cases/secrules-language-tests

.venv/bin/python benchmarks/scripts/bench_modsecurity_units.py \
  --modsecurity-root /tmp/sentinel-modsecurity-replay \
  --out /tmp/sentinel-modsecurity-units.json
```

语言测试子模块固定于 `f73c73027ef49ccf99c7911744929a71d15ff419`。
适配器读取全部 operators/transformations JSON，以及父仓库 unit JSON，共 4,359 项。
算子比较返回布尔值，转换函数比较输出字节，口径与官方 unit runner 一致。
不支持的算子、转换、外部数据库、捕获断言及原生错误注入钩子单列；它们仍计入总数和分类平均分分母。
这是函数级适配测试，未构建/执行 libmodsecurity，也不能替代完整规则链或代理验证。
IP 匹配占 3,623 项，因此报告同时给出按每种操作等权的平均通过率。

当前项目的 CRS 规则来自固定 commit `30cb436b261a9f5ec32a5a0677e17f3cfa1a8739`，
通过 `tools/vendor.py --only crs` 同步，原有 `crs-setup.conf` 保留。
重测当前规则使用新的输出文件，勿覆盖 §8 的旧规则基线。

## MDN HTTP Observatory 被动响应头基准

```bash
git init /tmp/sentinel-observatory-replay
git -C /tmp/sentinel-observatory-replay remote add origin https://github.com/mdn/mdn-http-observatory.git
git -C /tmp/sentinel-observatory-replay fetch --depth 1 origin c33d9fccd75088d4f9c48d2d379a2f2ae371136b
git -C /tmp/sentinel-observatory-replay checkout --detach FETCH_HEAD

.venv/bin/python benchmarks/scripts/bench_observatory.py \
  --observatory-root /tmp/sentinel-observatory-replay \
  --out /tmp/sentinel-observatory.json
```

读取 `x-content-type-options.test.js`、`referrer-policy.test.js`、`cross-origin-resource-policy.test.js`、
`cross-origin-opener-policy.test.js`、`cross-origin-embedder-policy.test.js` 中的字段样本及 pass 断言，
展开 52 项用例；不执行 JS、npm 安装或网络扫描。
只评估有无相应配置提示，不比较 Observatory 的网站评分或风险等级。
2 项 Referrer-Policy HTML meta 子用例单列不支持；其余模块未纳入本次适配范围。
`observatory-before.json` 是添加检测器之前的旧三类头基线；`observatory-round4-before.json` 是扩展至五类头、
但尚未添加 COOP/COEP 检查的 52 项基线。比较时必须保持同一批用例，不能把未告警当作安全证明。
当前复测还应运行 `tests/test_passive_headers.py`、`tests/test_waf_multipart.py`、`tests/test_modsecurity_units.py`。

## Naxsi 上游静态 fixture

```bash
git init /tmp/sentinel-naxsi-replay
git -C /tmp/sentinel-naxsi-replay remote add origin https://github.com/nbs-system/naxsi.git
git -C /tmp/sentinel-naxsi-replay fetch --depth 1 origin a59462b8c2f9c2c0c0fbc3ceb287ee5d60b652c3
git -C /tmp/sentinel-naxsi-replay checkout --detach FETCH_HEAD
.venv/bin/python benchmarks/scripts/bench_naxsi_fixtures.py \
  --naxsi-root /tmp/sentinel-naxsi-replay \
  --out /tmp/sentinel-naxsi-fixtures.json
```

该仓库为项目规则所来自的已归档上游；核心规则必须与 vendor 字节一致，否则脚本报错。
读取 527 个测试块，当前适配 145 个静态请求的 error_code 允许/拦截含义。
不执行 Perl、nginx、原始报文、响应正文/日志断言或复杂路由；382 个未支持块仍计入总分母。
没有 Content-Type 的有正文请求在适配器中按表单处理，属于明确的适配约定。

## 普通请求的代理端到端基准

```bash
.venv/bin/python benchmarks/scripts/bench_proxy_benign.py \
  --requests 120 --repeats 3 \
  --out /tmp/sentinel-proxy-benign.json
```

只绑定 `127.0.0.1` 随机端口，使用独立回显后端，不启动项目漏洞靶场。
脚本自行关闭代理和后端、清理临时审计文件。测试 6 种普通 GET/表单/JSON/XML 请求；
按目标、方法、正文哈希验证转发完整性。每个配置在并发 1/8 下各跑 3 次，默认每次 120 请求。
完成速率包含客户端、TCP 建连、后端及审计开销，也包括被拒绝的请求；不是纯 WAF 吞吐上限。
`proxy-benign-before.json` 是初次 6 请求/1 次的冒烟记录，不能与最终负载测量作性能涨跌比较。

## 环境

```bash
# 靶场
docker run -d --name sentinel-juice -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run -d --name sentinel-dvwa  -p 127.0.0.1:8081:80   vulnerables/web-dvwa
# DVWA 初始化: 访问 /setup.php 建库 -> admin/password 登录 -> security=low

# 外部载荷 (联网自行拉取)
export SENTINEL_BENCH_PAYLOADS=/tmp/opencode/payloads
mkdir -p "$SENTINEL_BENCH_PAYLOADS"
git clone --depth 1 https://github.com/wallarm/gotestwaf          "$SENTINEL_BENCH_PAYLOADS/gotestwaf"
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings "$SENTINEL_BENCH_PAYLOADS/PayloadsAllTheThings"
```

`bench_waf.py` 依赖 `PyYAML`（`pip install pyyaml`）。

## 用法

```bash
PY=/home/nonmirror/Projects/sentinel/.venv/bin/python
S=benchmarks/scripts
OUT=/tmp/opencode/results

# WAF: GoTestWAF 专用用例 (PL1 / PL2 / PL4)
for pl in 1 2 4; do "$PY" $S/bench_waf.py --source GoTestWAF --paranoia $pl --out $OUT/waf-gtw-pl$pl.json; done
# WAF: 全量语料
"$PY" $S/bench_waf.py --paranoia 1 --out $OUT/waf-pl1.json
# WAF: 端到端代理
"$PY" $S/bench_waf_proxy.py --engine modsecurity --attacks 400 --benign 120 --out $OUT/waf-proxy.json
# WAF: 完整固定语料、balanced 配置
"$PY" $S/bench_waf_proxy.py --engine modsecurity --source GoTestWAF \
  --profile balanced --paranoia 4 --attacks 434 --benign 169 --out $OUT/waf-balanced-proxy.json
# WAF: 已在本机启动的竞品反向代理
"$PY" $S/bench_waf_proxy.py --engine peer-name --endpoint http://127.0.0.1:18080 \
  --source GoTestWAF --paranoia 1 --attacks 434 --benign 169 --out $OUT/waf-peer.json
# 扫描器: 自带靶场 / 第三方应用 / 检测器级
"$PY" $S/bench_lab.py --out $OUT/lab-multi.json
"$PY" $S/bench_multi.py --targets ../data/20261018/targets-juice.json --out $OUT/juice-multi.json
"$PY" $S/bench_detectors.py --cases ../data/20261018/cases-dvwa.json \
      --cookie "PHPSESSID=...; security=low" --out $OUT/dvwa-detectors.json
```

> **授权提醒**：这些脚本会主动发起攻击载荷。只对本地靶场或已获书面授权的目标使用。


## HTTPWG 结构化字段组件基准

```bash
git init /tmp/sentinel-httpwg-replay
git -C /tmp/sentinel-httpwg-replay remote add origin https://github.com/httpwg/structured-field-tests.git
git -C /tmp/sentinel-httpwg-replay fetch --depth 1 origin 781ba38464b2ec4c547e1e14d007d4f5ace7457e
git -C /tmp/sentinel-httpwg-replay checkout --detach FETCH_HEAD
.venv/bin/python benchmarks/scripts/bench_structured_headers.py \
  --httpwg-root /tmp/sentinel-httpwg-replay \
  --out /tmp/sentinel-httpwg-items.json
```

扫描根目录解析 JSON 共 1,598 项；执行 839 项必需 Item 用例，751 项非 Item 容器、8 项可选接受用例单列。
仅验证接受/拒绝与主 token，未比较完整类型树、参数值或序列化；不执行 `serialisation-tests/`。
这是扫描器 COOP/COEP 检查所用解析组件的标准兼容性证据，不是第三套漏洞扫描框架或漏洞检出率。


## CRS 检测等级与拦截等级分离

原 `waf.paranoia_level` 继续决定拦截等级。新增可选 `waf.detection_paranoia_level`，
默认 `null`，此时行为不变；仅用于原生 ModSecurity/CRS 引擎。实际检测等级不会低于拦截等级。
例如 JSON 配置片段：

```json
{"waf": {"paranoia_level": 1, "detection_paranoia_level": 4}}
```

这会记录较高等级规则的命中，但它们不计入 PL1 拦截分数。它是分阶段调优工具，不能当作 PL4 拦截能力。
生效的两个等级可从引擎 `health()` 查看。无需修改规则文件或降低异常评分阈值。

```bash
SENTINEL_BENCH_PAYLOADS=/tmp/opencode/payloads .venv/bin/python benchmarks/scripts/bench_waf_policy.py \
  --repeats 3 --out /tmp/sentinel-waf-policy.json
.venv/bin/python benchmarks/scripts/bench_proxy_benign.py --split-crs \
  --requests 120 --repeats 3 --out /tmp/sentinel-proxy-split.json
```

第一项是原有公开语料的新配置矩阵，不新增公开来源数。第二项在原 5 个配置基础上增加检测 PL4 / 拦截 PL1，
因此为 6 配置、4,320 个普通请求；前 5 个配置仍可分别与旧测量比较。

## Express 与重复响应头扩展

保留上一节的 Python 独立环境，另建 npm 环境（不在项目根目录安装依赖）：

```bash
mkdir -p /tmp/sentinel-express-replay
cp benchmarks/data/20261018/express-package-round7.json /tmp/sentinel-express-replay/package.json
cp benchmarks/data/20261018/express-package-lock-round7.json /tmp/sentinel-express-replay/package-lock.json
npm ci --prefix /tmp/sentinel-express-replay --ignore-scripts --no-audit --no-fund
.venv/bin/python benchmarks/scripts/bench_frameworks.py \
  --framework-python /tmp/sentinel-framework-replay/bin/python \
  --express-root /tmp/sentinel-express-replay --extended --repeats 3 \
  --out /tmp/sentinel-frameworks-extended.json
```

本次 Node **26.8.1**、Express **5.3.0**、Multer **2.4.0**；完整 npm 依赖及完整性摘要记录在 lockfile。
`framework_express.cjs` 使用 Express 的 JSON／URL 编码解析器和 Multer 的内存上传解析器，
只绑定回环地址；JSON／URL 编码正文上限 1 MiB，单上传文件上限 1 MiB，最多 2 个文件及 10 个字段，不持久化上传。

`--extended` 加入两个 Cookie 和重复策略字段，保留原 10 个用例，共 12 种请求。
Python 应用用各框架 `set_cookie` API，重复策略字段由测试 ASGI 中间件追加；Express 使用其响应 API。
检查重复字段的数量、值和顺序；不会将排序后的同名字段误计为原序转发。
4 个框架 × 6 个配置 × 12 个用例 × 3 次 = 864 次计量请求。
被动响应头为 4 个框架 × 4 种配置场景 × 6 条路径 × 3 次 = 288 项检查。
这些重复测量不是独立漏洞样本；未带两个可选参数时仍运行原三个框架、10 种请求。

`frameworks-round7-before.json` 和 `frameworks-round7-after.json` 是同语料、同依赖的修复前后结果。
该扩展仍属于一个自建集成套件，不增加公开第三方 benchmark 来源数量。

## CRS 集合语义复测（第八轮）

`bench_crs_fixtures.py` 继续使用相同 fixture 和规则 ID 期待值，不应用 httpd/nginx 平台覆盖文件，
也不替测试修改 ARG_NAME_LENGTH、MAX_NUM_ARGS 等阈值。新输出增加 `slowest_cases`，记录最慢十项的规则求值耗时，
仅用于定位性能问题；单次、未隔离 CPU，不作为生产延迟结论。

第八轮修复请求头／Cookie 正则选择器、正则排除的大小写语义、无等号 Cookie 名称、
根路径空 basename 及反斜杠路径分隔。定向回归位于 `tests/test_secrule_collections.py`，使用普通标记，不发网络请求。
ModSecurity 正文上限热更新另由 `tests/test_waf_policies.py` 验证。

同轮修复正则开头贪婪字符类的冗余搜索，包括顶层备选分支；仅适用于从偏移 0 开始的单次搜索。
`tests/test_regex_search_cost.py` 验证匹配位置、捕获组及普通长字符串的完成时间。
`crs-fixtures-round8-before-cost-fix.json` 与 `crs-fixtures-round8.json` 是同 fixture 的优化前后记录。
`crs-latency-diagnostic-round8.json` 含人为诊断超时，`crs-latency-profile-round8.json` 是中间实现的定位数据；
二者均不替代最终质量结果，也不构成生产延迟保证。

第八轮尚未展开 `920400.yaml` 的两个 go-ftw `repeat` 正文模板。第九轮已补支持，见下节；
旧结果保留为历史快照，不据其负向通过声称展开后的官方请求已经执行。


## 模板展开与 multipart 参数语义（第九轮）

`bench_crs_fixtures.py` 现在展开正文中的双引号普通字符串 `repeat` 表达式。
支持同一正文的多个表达式、零次重复和 UTF-8 文本；不支持带反斜杠转义的模板字符串、
环境读取、随机函数及其他 Go 模板语法。未知表达式列入 `unsupported-body-template`；
展开正文总量超过 1 MiB 列入 `template-size-limit`，均不算通过，不执行模板代码。

先展开再计算缺省 Content-Length；fixture 显式给出的 Content-Length 保留原值。
固定 CRS 语料目前只有 `920400.yaml` 两项实际正文模板，重复次数为 64200 和 152。
`crs-template-audit-round9.json` 保存展开后的长度及摘要；`crs-fixtures-round9-adapter.json`
是只修模板后的结果，`crs-fixtures-round9.json` 是上传参数修复后的最终结果。
源 fixture 哈希虽相同，两个实际正文已经变化，不把跨轮所有请求称为完全相同。

上传参数使用标准库兼容解析保留非引号、非反斜杠的反斜杠转义；继续用现代 MIME 解析检查缺陷。
`tests/test_waf_multipart.py` 覆盖路径、字段名、转义引号、双反斜杠、UTF-8 扩展参数及折行。
这修复了 CRS 的五项上传字段差异，不等同于全部 multipart 语法或后端行为兼容。


## WPT 响应头解析（第十轮）

```bash
git clone --filter=blob:none --sparse https://github.com/web-platform-tests/wpt.git /tmp/sentinel-wpt-replay
git -C /tmp/sentinel-wpt-replay sparse-checkout set fetch/nosniff fetch/cross-origin-resource-policy
git -C /tmp/sentinel-wpt-replay checkout c47791d69da614474168c0f6c1ad9a1dbd0cf0d3
.venv/bin/python benchmarks/scripts/bench_wpt_headers.py \
  --wpt-root /tmp/sentinel-wpt-replay --out /tmp/sentinel-wpt-headers.json
```

固定版本读取 `fetch/nosniff/resources/x-content-type-options.json` 的全部15项及
`fetch/cross-origin-resource-policy/syntax.any.js` 的全部7项表格输入；记录另外两个上游辅助源文件摘要。
不启动 WPT 服务器或浏览器，不执行其 JavaScript，不发出请求。
模板／表格结构变更无法识别时显式失败，不默默跳过或推导新的期待值。

`nosniff` 表格的期待是保护是否按 Fetch 首值规则生效；CORP 表格的期待是头部值无效的观察。
`configuration_alert` 独立记录格式告警，非规范重复 nosniff 可以同时“保护生效”及“格式需修正”。
这是一个新增公开协议测试来源，不能视为完整 WPT 通过或新增主动漏洞检测能力。
修改前后结果分别为 `wpt-headers-round10-before.json`、`wpt-headers-round10-after.json`。


## URL 编码参数的字节语义（第十一轮）

SecRule 的 GET 参数和 URL 编码 POST 参数现在通过同一 `query_pairs` 函数解码，
把百分号编码还原为 Latin-1 字符串表示的原始字节，不提前按 UTF-8 替换或合并字符。
原始 HTTP 字节与等价百分号编码输入保持一致；加号、空值、重复参数和单次解码规则保留。
自定义规则的 `length`、捕获组及非 ASCII 参数比较会遵循字节语义，不能继续假定 ARGS 已经是 UTF-8 文本。

`tests/test_secrule_bytes.py` 用普通标记验证全部256种字节、原始／百分号输入等价性、
非法UTF-8参数名的区分、显式UTF-8转换和正文处理器覆盖。
`crs-decoding-diagnostic-round11.json` 只是在22项旧失败上替换解码方式的定位实验，
不是完整成绩；最终成绩是 `crs-fixtures-round11.json`。
本轮未改变 JSON/XML、文件名或路径集合的编码约定，不声称所有 Unicode 语义已统一。


## CRS 请求字节与转换语义（第十二轮）

CRS 适配器现在先把 YAML 请求目标和头部字符串编码为 UTF-8，再按真实 `parse_request` 的
Latin-1 字节容器约定构造 `HttpRequest`。源 fixture 哈希不变，但13项内存输入表示变化，
其中5项请求目标、8项头部；审计见 `crs-wire-audit-round12.json`。
这一修正以 go-ftw 提交 `b2dfd8884efecd5e20a0eb433d88a39cac9e83e0` 的请求行／头部写入代码为依据，
没有运行原生 go-ftw 网络测试。`crs-fixtures-round12-adapter.json` 单独记录适配修正后的成绩。

SecRule 的大小写、trim、compressWhitespace 和 cmdLine 小写处理改为 C-locale 的字节语义。
removeWhitespace 还按上游实现移除 `0xC2` 与 `0xA0`，即使它们没有组成完整字符。
ASCII 输入仍走原有快速大小写路径；非 ASCII 字节不再被 Unicode 大小写规则改写或扩展。
`tests/test_secrule_bytes.py` 新增8项普通字节回归；这不是通用 Unicode 文本处理接口。

`crs-fixtures-round12.json`、`modsecurity-unit-round12.json` 和 `regressions-round12.json`
是最终实现的复测结果；不要把适配器校正带来的9项通过增加归因于新增检测规则。


## 可选上游大小限制配置（第十三轮）

默认 CRS 复测命令不变。新增独立配置，仅用于对照上游测试容器显式启用的限制：

```bash
.venv/bin/python benchmarks/scripts/bench_crs_fixtures.py \
  --crs-root /tmp/sentinel-crs-public-bench --upstream-test-limits \
  --out /tmp/sentinel-crs-test-limits.json
```

从固定版本 `tests/docker-compose.yml` 的 `x-common-env` 读取四项：
ARG_LENGTH=400、TOTAL_ARG_LENGTH=6400、MAX_FILE_SIZE=64100、COMBINED_FILE_SIZES=65535。
只接受正整数，生成临时 SecAction 后加载；不修改项目配置、vendor规则或fixture期待值。
结果记录四项数值和配置文件摘要。未启用这个选项时不注入任何限制。
不加载平台覆盖文件；所以两个被上游 httpd 覆盖为不期待命中的项目仍保留原始正向期待，并记为失败。

`crs-fixtures-round13-default.json` 是默认配置成绩；`crs-test-limits-round13-before.json` 和
`crs-test-limits-round13-after.json` 是相同显式配置在修复 ARGS_COMBINED_SIZE 前后的成绩。
不能将不同配置的通过率直接归因为引擎改进。相关来源与六项大小观察见
`crs-size-profile-audit-round13.json`。

ARGS_COMBINED_SIZE 现在返回当前参数集合中名称与值的字节长度总和，保留重复值，排除上传文件内容。
JSON文本按UTF-8计字节，URL编码字段沿用原始字节表示；正文处理器切换后重新求值。
无参数时是存在的0标量。测试覆盖普通边界、混合GET/POST、Unicode、文件排除及配置输入校验。
该计数基于当前已解析集合，不是对所有原生JSON/XML处理和phase可见性的全面兼容声明。


## 四框架请求正文上限（第十四轮）

```bash
.venv/bin/python benchmarks/scripts/bench_proxy_body_limits.py \
  --framework-python /tmp/sentinel-framework-replay/bin/python \
  --express-root /tmp/sentinel-express-replay --repeats 3 \
  --out /tmp/sentinel-body-limits.json
```

复用前述 Django、Flask、FastAPI、Express 环境与普通表单回显端点。
将 `max_body_bytes` 显式设为1024，发送1023、1024、1025字节的普通表单；
前两者要求200及完整正文摘要／字段，后者要求413。每组随后用新连接检查普通GET仍为200。
每个框架覆盖 python、naxsi、modsecurity 三引擎的 block、detect、off 三模式，均为PL1，重复3次。
共4×3×3×4×3＝432项；直连校验和启动探活不计入。后端超时两次测量均固定为0.5秒。
这是原有自建集成套件的扩展，不是新增公开基准来源，也不是新增主动扫描测试。

`body-limits-round14-before.json` 为修复前结果，`body-limits-round14-after.json` 为修复后结果；
语料、配置、框架依赖与期待不变。原有套件另存 `frameworks-round14.json`，不将预期413混算为完整转发。

代理现在在读取声明的超限正文前返回413并关闭连接，不再转发被解析器截断的内容。
该资源限制独立于检测模式和 `inspect_body`，默认仍为131072字节；0只允许空正文。
限额内普通请求不变，运行中调低限制导致的截断也明确拒绝。
这不是分块请求、Expect握手、所有畸形请求处理或进程内存上界的完整验证。


## Chromium Referrer-Policy 公开单元样本（第十五轮）

新增公开来源 Chromium，固定提交 `92e02bfafbc4a8bd68d536fb88852e08f0aa5a12`。
只下载两份源码，不构建或运行浏览器，不启动主动扫描。准备命令：

```bash
.venv/bin/python - <<'PY'
import base64, json, urllib.request
from pathlib import Path
root = Path('/tmp/sentinel-chromium-header-replay')
root.mkdir(exist_ok=True)
source = 'https://chromium.googlesource.com/chromium/src/'
commit = '92e02bfafbc4a8bd68d536fb88852e08f0aa5a12'
for name in ('security_policy.cc', 'security_policy_test.cc'):
    url = source + '+/' + commit + '/third_party/blink/renderer/platform/weborigin/' + name + '?format=TEXT'
    with urllib.request.urlopen(url, timeout=30) as response:
        (root / name).write_bytes(base64.b64decode(response.read()))
(root / 'source.json').write_text(json.dumps({'source': source, 'commit': commit}) + '\n')
PY
.venv/bin/python benchmarks/scripts/bench_chromium_headers.py \
  --chromium-root /tmp/sentinel-chromium-header-replay \
  --out /tmp/sentinel-chromium-headers.json
```

适配 `ReferrerPolicyFromHeaderValue` 的6个非legacy表项；1个legacy表项明确记未支持。
另适配 `ReferrerPolicyToAndFromString` 的8个标准策略字符串，检查策略选择结果；
不声称执行了原生序列化器。适配器校验原断言和表结构，未知结构报错，不静默略过。
结果含源码路径、固定提交、SHA-256、原始输入、期待和实际策略。
`chromium-headers-round15-before.json`／`chromium-headers-round15-after.json` 为同语料修复前后。

Referrer-Policy 现在区分合法未知名称与非法语法：名称只允许ASCII字母和连字符；
任一非空表项语法非法时，整个字段无效，不能保留其他表项提供的策略。
合法未知名称仍忽略，最后一个已知策略仍优先；大小写不敏感，边缘仅去除HTTP空格和制表符。
观察结果仍是INFO，不代表浏览器执行或已确认信息泄露。

四框架集成新增两个可选策略边界场景，原有默认语料不变：

```bash
.venv/bin/python benchmarks/scripts/bench_frameworks.py \
  --framework-python /tmp/sentinel-framework-replay/bin/python \
  --express-root /tmp/sentinel-express-replay --extended --referrer-boundaries --repeats 3 \
  --out /tmp/sentinel-frameworks-referrer.json
```

`no-referrer, origin no-referrer` 应报告无效；`no-referrer, future-policy` 不应报告无效。
四框架×六路径×两场景×三次新增144项；其中72项应有Referrer-Policy提示、72项不应有。
扩展套件共1008项转发及432项被动检查，不能直接把它与旧864项／288项的比例当作同语料提升。
同语料对照见 `frameworks-round15-before.json`／`frameworks-round15-after.json`。


## 字节范围校验成本与普通请求判定（第十六轮）

```bash
.venv/bin/python benchmarks/scripts/bench_byte_ranges.py --repeats 5 \
  --out /tmp/sentinel-byte-ranges.json
```

自建离线性能检查，使用普通字母与空格，不发送HTTP，也不增加公开基准来源数。
覆盖 `0-255` 和 CRS PL4 规则920273的字符范围，长度为0、32、1024、8192、65536、131072；
非空输入分别放置首部／中间／尾部空格或全部字母，共42组，每组5轮。
每轮调用次数固定为 `max(1, min(100, 65536 // max(1, size)))`，结果记录全部样本和中位数。
另运行1、8、64 KiB普通表单的完整PL4引擎检查，各5轮；框架14个用例的命中轨迹另外记录。

`byte-ranges-round16-before.json`／`byte-ranges-round16-after.json` 使用相同输入和配置。
耗时包含函数调用、编码及判定一致性检查；热缓存、串行、未隔离CPU，不能换算成代理吞吐。
框架轨迹是离线重建请求，真实框架集成结果另见 `frameworks-round16.json`。

实现把范围编译成有界缓存中的单字节字符类，交给底层正则搜索首个不允许的字节。
不使用重复量词或改变允许集合；全256字节允许时直接通过集合检查。
14组范围逐一测试全部256个单字节及组合值，并覆盖空值、范围重叠、极大边界、
首／中／尾不允许字节、Latin-1替换及算子取反，共22项针对性回归。
历史非法范围参数的容错语义保留，原生初始化错误差异未在这次性能修改中解决。


## SecRule JSON 数组名称与公开集合回归（第十七轮）

```bash
.venv/bin/python benchmarks/scripts/bench_json_collections.py \
  --modsecurity-root /tmp/sentinel-modsecurity-public-bench \
  --out /tmp/sentinel-json-collections.json
```

复用既有固定版本 ModSecurity 源码，读取 `test/test-cases/regression/issue-1576.json` 的三个普通JSON样本。
将其正文行按LF拼接，只验证上游期待的字段值／变量名称在ARGS集合中可见。
不执行上游phase-3规则、原生日志或HTTP状态断言；不发送请求。
该回归与已有ModSecurity算子基准属于同一公开来源，不能额外计一个来源或合并成原生全套通过率。
`json-collections-round17-before.json`／`json-collections-round17-after.json` 保存同语料前后结果。

SecRule现在将数组索引命名为 `.array_0`、`.array_1` 等，例如 `json.tags.array_1`。
根数组、嵌套数组、空容器占位后的索引及重复对象键均保留；真实字段名中的方括号不改写。
完整原始正文和全部字段值仍参与原有检测，公共解析器默认的 `tags[0]` 命名与Naxsi的无索引命名保持不变。
名称长度变化会同步反映到ARGS_COMBINED_SIZE；正文处理器切换后重新计算缓存。

**兼容性注意：** 自定义SecRule若按旧生成名称 `ARGS:json.tags[1]` 选择数组项，
需改为 `ARGS:json.tags.array_1`。没有自动重写字面方括号键或添加混淆别名。
此改动针对数组名称，不声明完全统一原生JSON空键、数字／布尔文本、深度限制或所有phase可见性。

`json-array-audit-round17.json` 比较同14种普通框架输入的命中记录。
JSON与vendor-json少了生成名称导致的921220／942432，但原始正文仍触发920273，默认PL4仍会拒绝这两种请求。
四框架真实集成另见 `frameworks-round17.json`，不能把命中数下降当成拒绝数下降。


## JSON 标量与 JSONTestSuite（第十八轮）

固定公开来源 `https://github.com/nst/JSONTestSuite`，提交 `1ef36fa01286573e846ac449e8683f8833c5b26a`：

```bash
git clone https://github.com/nst/JSONTestSuite /tmp/sentinel-json-testsuite-replay
git -C /tmp/sentinel-json-testsuite-replay checkout 1ef36fa01286573e846ac449e8683f8833c5b26a
.venv/bin/python benchmarks/scripts/bench_json_parser.py \
  --json-suite-root /tmp/sentinel-json-testsuite-replay \
  --out /tmp/sentinel-json-parser.json
```

离线运行 `test_parsing` 全部318个文件；每个输入在独立子进程解析，5秒超时。
95个y_必须接受，188个n_必须拒绝；35个i_仅记录接受／拒绝，不能算作通过。
超时／崩溃单独计数，不能算成成功拒绝。22个 `test_transform` 文件未执行，结果保留清单。
不发送HTTP，不运行上游原生runner；此入口验证正文解析组件，不能表述为WAF攻击覆盖率。
`json-parser-round18-before.json`／`json-parser-round18-after.json` 为同语料对照：280/283变为283/283。

共享解析器保留数字词法原文及小写布尔值；NaN／Infinity／-Infinity为错误，引号内同名字符串仍有效。
解析错误保留原文检测，SecRule设置REQBODY_ERROR；并非无条件返回HTTP拒绝。
null、重复键、各引擎数组命名及深度限制保持原约定。
自定义规则若依赖旧Python数值／布尔字符串，需要改用收到的JSON文本；ARGS_COMBINED_SIZE同步按新字段文本计算。

四框架增加可选普通标量场景，默认语料保持不变：

```bash
.venv/bin/python benchmarks/scripts/bench_frameworks.py \
  --framework-python /tmp/sentinel-framework-replay/bin/python \
  --express-root /tmp/sentinel-express-replay --extended --referrer-boundaries --json-scalars \
  --repeats 3 --out /tmp/sentinel-frameworks-json-scalars.json
```

共15输入×4框架×6路径×3次，即1,080请求。新场景包含普通布尔、null、负零、小数和指数，
核对后端解析值及原始正文摘要；不使用JavaScript无法准确表示的巨大数值。
本轮同语料修复前后均996/1,080完整转发，84次PL4误拦；被动检查仍432/432。
原14输入子集936/1,008未变。标量正确性另外用29项回归验证，不能仅从转发率推导。

## balanced WAF 验收（2026-10-19，第二十轮）

本节记录上一轮85%／10%验收；当前95%目标及新增检查见下一节。

`balanced` 是 Sentinel SecRule/CRS 引擎的显式评分配置，默认仍为 `standard`。
保留56条经语义指纹校验的规则命中和类别分，把它们的入站异常分移入辅助分池。
辅助分不能单独阻断，只有另有非辅助证据时才能追加最多2分；单独的旧字符编码告警不算该证据。
明确deny动作、检测等级与阻断等级的隔离保持有效；不是业务路径、词语或样本哈希白名单。
规则升级后指纹不符的项维持标准评分，并在健康检查中报告告警。

启用示例（本轮没有替用户启动长期服务）：

```bash
.venv/bin/python -m sentinel tui --config examples/waf-balanced.toml --engine modsecurity
```

已有配置可复制示例中的 `[waf]` 字段。此配置仅作用于 `modsecurity` 原生解释器，
不自动改变Python、Naxsi或原生nginx参考数据面的行为。阈值仍为5，阻断与检测等级均为4。

GoTestWAF依赖沿用上文固定版本及本项目载入路径。固定分区包含全部434正向和169良性请求；
初次验证失败后已参与调整，因此后续运行只能称为回归，不能重新宣称盲测。

```bash
.venv/bin/python benchmarks/scripts/bench_waf_acceptance.py \
  --manifest benchmarks/data/20261019/waf-acceptance-split.json --repeats 3 \
  --out /tmp/sentinel-balanced-acceptance.json

curl -fL 'https://redata.anii.org.uy/api/access/datafile/389' \
  -o /tmp/sentinel-csic-normal.txt
.venv/bin/python benchmarks/scripts/bench_csic_benign.py \
  --normal-file /tmp/sentinel-csic-normal.txt --sample-size 2000 --offset 0 \
  --out /tmp/sentinel-csic-development.json
.venv/bin/python benchmarks/scripts/bench_csic_benign.py \
  --normal-file /tmp/sentinel-csic-normal.txt --sample-size 4000 --offset 2000 \
  --out /tmp/sentinel-csic-holdout.json

.venv/bin/python benchmarks/scripts/bench_frameworks.py \
  --framework-python /tmp/sentinel-framework-replay/bin/python \
  --express-root /tmp/sentinel-express-replay --extended --referrer-boundaries --json-scalars \
  --crs-profile balanced --repeats 3 --out /tmp/sentinel-frameworks-balanced.json
```

CSIC文件来自公开研究数据集WebRequests中附带的CSIC 2010正常训练集，
SHA-256为 `d3344377d4721b03b906ca232ab44bfd81b9c1356f967ec9d348532ec420f000`。
脚本验证摘要后读取36,000条完整请求；只移除记录间空行，保留原请求目标、头、正文和长度。
前2,000条用于诊断，随后冻结代码再分类下4,000条；两组不重叠，剩余30,000条未分类。
它是同源正常流量留出验证，不是独立应用、生产流量或未见攻击验证。

最终结果与失败快照见报告§28及 [`../data/20261019/`](../data/20261019/)。
所有误报率按各自良性分母单列；不靠扩大良性总分母稀释旧语料误报。

## balanced WAF：95%召回与约5%误报（第二十一轮）

沿用 `examples/waf-balanced.toml`，默认配置仍为standard。
balanced的辅助规则由56条变为55条：942440恢复标准评分，其余辅助评分上限不变。
新增5项有长度界限的语法检查，识别间接JavaScript调用、LDAP过滤片段、换行后的SMTP信封指令、
带分隔符的命令语法及选项赋值中的命令替换结构。检测PL至少2才生效；阻断PL1／检测PL4时只观察。
检查原值及规范化中间值，保留原始加号等可能被后续解码改变的语法。
这些规则只提供请求侧证据，不证明后端执行，也不是完整语言解析器。
没有新增GraphQL内省禁令或按工具名称拒绝的规则。

“约5%”在本轮固定为各良性集合误报率严格低于5.5%；低于5%也接受，不人为增加误报。
整体请求加权和全部21类别等权的召回均要求至少95%。脚本默认保留旧门槛以便复现历史，
**本轮必须显式传入新门槛**：

```bash
.venv/bin/python benchmarks/scripts/bench_waf_acceptance.py \
  --manifest benchmarks/data/20261019/waf-acceptance-split.json \
  --min-recall .95 --max-fpr .055 --repeats 3 \
  --out /tmp/sentinel-waf95-acceptance.json

# 原先检查过的6,000条正常请求，作为回归集。
.venv/bin/python benchmarks/scripts/bench_csic_benign.py \
  --normal-file /tmp/sentinel-csic-normal.txt --sample-size 6000 --offset 0 \
  --out /tmp/sentinel-waf95-csic-regression.json

# 冻结本轮策略后首次分类的10,000条；与前6,000条无交集。
.venv/bin/python benchmarks/scripts/bench_csic_benign.py \
  --normal-file /tmp/sentinel-csic-normal.txt --sample-size 10000 --offset 6000 \
  --out /tmp/sentinel-waf95-csic-holdout.json

# 将完全相同的留出请求回放到已启动的第三方WAF HTTP数据面；只有403计误报。
.venv/bin/python benchmarks/scripts/bench_csic_benign.py \
  --normal-file /tmp/sentinel-csic-normal.txt --sample-size 10000 --offset 6000 \
  --endpoint http://127.0.0.1:18080 --engine modsecurity-crs-official \
  --profile standard --paranoia 1 --threshold 5 \
  --out /tmp/modsecurity-pl1-csic-holdout.json

.venv/bin/python -m pytest tests/test_crs_profiles.py tests/test_balanced_syntax.py -q
```

四框架复现命令同上一节，仍使用 `--crs-profile balanced`。
正向样本继续使用开发过的434条，旧字段名validation的分区仍非盲测；
本轮新增留出仅验证正常请求误报，不能作为未知攻击召回证明。最新结果见报告§29。
