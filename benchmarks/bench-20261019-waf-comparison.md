# 高关注开源WAF同语料对照

日期：2026-10-19。测试只在本机回环和Docker网络内进行。

**结论：Sentinel `balanced` 是本轮唯一兼顾高拦截和低误报的配置。** 它在434条攻击和169条良性请求上以 **95.39%／95.15%／2.96%** 通过95%／95%／5%门槛，在相同10,000条CSIC冻结留出正常请求上误报 **5.08%**。CRS PL1的CSIC误报略低，为4.86%，但攻击总体拦截只有78.80%；高召回PL4则误拦全部CSIC请求。

## 1. 项目与版本

GitHub星数取自2026-10-19 API快照。星数只衡量社区关注度，不是质量认证。

| 项目 | GitHub星数 | 本轮实现与固定版本 | 状态 |
|---|---:|---|---|
| [SafeLine](https://github.com/chaitin/SafeLine) | 22,780 | `7dee6104`；detector 9.2.7，镜像digest `601fae21` | 已探测；未评分 |
| [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) + [OWASP CRS](https://github.com/coreruleset/coreruleset) | 9,811 + 3,307 | 官方`modsecurity-crs:nginx`，digest `7698c48a`，2026-10-14构建 | 已完成PL1、PL4 |
| [NAXSI](https://github.com/nbs-system/naxsi) | 4,804 | 原生nginx模块，tag 1.3，commit `b77c1726` | 已完成基准阈值档 |
| [Coraza](https://github.com/corazawaf/coraza) + OWASP CRS | 3,910 + 3,307 | 官方`coraza-crs:nginx`，digest `e23a8fc`，2026-09-14构建 | 已完成PL1、PL4 |

WAF属于小众基础设施类别，因此没有沿用扫描器“≥10,000星”门槛。这里选择该类别中关注度最高或公认的主流开源实现，并公开实际星数。

## 2. 统一口径

- 攻击集：Wallarm GoTestWAF固定提交`8ed7bc210ab7530c83b00e591136847307635207`，21类、434条HTTP请求。
- 良性集：GoTestWAF正常文本展开94条，加项目固定良性请求75条，共169条。
- 正常留出集：公开CSIC 2010正常训练流量去重后按SHA-256排序，固定取偏移6,000后的10,000条；各实现收到完全相同的7,795条GET和2,205条POST。
- 所有可评分实现接收相同原始HTTP报文。真实反向代理返回403才计WAF拦截；200、302、404、500均不计拦截。
- 后端仅提供统一转发目标。后端404或500被保留，但不会虚算成WAF命中。
- Sentinel使用目标配置`balanced`、PL4、阈值5。ModSecurity+CRS分别测推荐默认PL1和高召回PL4，阈值均为5。NAXSI使用原生Core Rules，并由本基准nginx包装器设置SQL/XSS/RFI等类别阈值；这不是NAXSI官方推荐策略。
- 质量排名只看拦截与误报。不同实现的代理、日志和后端路径不同，因此本轮QPS不作产品性能排名。

攻击集长度前缀摘要为`b12e622dfe48525e9537d955e14e24a3158397325379db8e10452bae5edb3bb1`；良性集为`a6b1e12a7437ca297ec3ac1004377efd211ce20ece82125af5f78bd4ea732e6b`。

## 3. 结果

| 实现／配置 | 总体拦截 | 类别等权拦截 | 169条良性误报 | CSIC 10,000条留出误报 | 验收 |
|---|---:|---:|---:|---:|---|
| **Sentinel balanced PL4** | **414/434，95.39%** | **95.15%** | **5/169，2.96%** | **508/10,000，5.08%** | **攻击与原良性三项全过；留出约5%** |
| ModSecurity + CRS PL1 | 342/434，78.80% | 72.77% | 20/169，11.83% | 486/10,000，4.86% | 召回、原良性未过 |
| Coraza + CRS PL1 | 342/434，78.80% | 72.77% | 20/169，11.83% | 486/10,000，4.86% | 召回、原良性未过 |
| NAXSI 1.3 基准阈值档 | 410/434，94.47% | 88.78% | 61/169，36.09% | 1,491/10,000，14.91% | 三项未过 |
| ModSecurity + CRS PL4 | 432/434，99.54% | 98.94% | 132/169，78.11% | 10,000/10,000，100% | 误报未过 |
| Coraza + CRS PL4 | 433/434，99.77% | 99.47% | 143/169，84.62% | 10,000/10,000，100% | 误报未过 |

Sentinel相对ModSecurity／Coraza+CRS PL1提高总体拦截 **16.59个百分点**，同时降低误报 **8.87个百分点**。相对NAXSI提高总体拦截 **0.92个百分点**，降低误报 **33.13个百分点**。两个CRS实现的PL4多拦18—19条攻击，却多误拦127—138条良性请求；它们不满足“误报约5%”的目标。

CSIC留出进一步显示了同一权衡：CRS PL1比Sentinel少误拦22条，但少拦72条攻击，且类别等权拦截低22.38个百分点。CRS PL4因10,000条CSIC请求都携带其高等级规则限制的`Accept-Charset`头而全部阻断。Sentinel是唯一同时取得两项至少95%的攻击拦截和约5% CSIC留出误报的配置。

Sentinel代理实跑结果与三次离线验收完全一致。NAXSI重复三次计数一致。官方ModSecurity容器与本机单独编译的数据面得到相同计数，排除了单一打包方式造成的偏差。

## 4. SafeLine探测为何不排名

SafeLine官方部署由PostgreSQL、管理面、detector、tengine、luigi、fvm和chaos等服务组成，并需创建受保护站点。为避免用Sentinel兼容层冒充竞品，本轮额外拉取官方`chaitin/safeline-detector:9.2.7`，按仓库SDK的T1K协议发送全部603条请求。

未接管理面策略的独立detector对434条攻击和169条良性请求返回完全相同、且当前SDK未记录的动作字节`,`，没有可核验的HTTP阻断状态。将它解释为全部放行或全部阻断都会制造虚假成绩，因此只保留[探测记录](data/20261019/waf-compare-safeline-probe.json)，不参与排名。

## 5. 结论边界

这次结果支持“Sentinel在该固定攻击／良性权衡测试中综合成绩最好”。它不支持“Sentinel全面强于这些项目”：正向语料已参与Sentinel开发，CSIC属于历史合成电商流量，且没有比较生产运维、规则生态、协议覆盖或长期吞吐。

10,000条CSIC结果全部通过真实HTTP数据面得到，六个配置均无传输错误。不同实现的代理和后端不同，非403状态也不同，因此只比较误报计数，不比较这轮延迟或状态分布。SafeLine仍因缺少管理面策略而未评分。

机器可读汇总见[waf-comparison.json](data/20261019/waf-comparison.json)和[CSIC横向汇总](data/20261019/csic-waf-comparison.json)，各实现逐请求结果见同目录`waf-compare-*.json`与`csic-compare-*.json`。复现入口为[bench_waf_proxy.py](scripts/bench_waf_proxy.py)和[bench_csic_benign.py](scripts/bench_csic_benign.py)。
