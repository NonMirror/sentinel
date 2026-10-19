# 高关注开源主动扫描器同靶场对照

日期：2026-10-19。测试只访问本机Docker容器中的DVWA和OWASP Juice Shop。

**结论：Sentinel在本轮固定口径下综合成绩最好。** 四个高星工具合计贡献19项经HTTP证据复核、去重后的能力观察，Sentinel复现 **19/19**，另发现3项有效暴露；两目标合计发送 **4,729次请求、0错误**，请求量仅为Nuclei的26.1%、Nikto的27.7%。

## 1. 项目与版本

GitHub星数取自2026-10-19 API快照。纳入条件为不少于10,000星且具备主动Web探测能力；星数只表示社区关注度。

| 项目 | GitHub星数 | 本轮固定版本 | 定位 |
|---|---:|---|---|
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | 38,734 | `6530184e`，1.10.10.11#dev | SQL注入专项扫描 |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 32,121 | 引擎v3.11.1；模板`008731b3`／v10.4.9 | 模板化漏洞与暴露扫描 |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | 15,964 | 2.17.0；镜像digest `5ccfff9a` | 爬虫、被动检查和主动DAST |
| [Nikto](https://github.com/sullo/nikto) | 10,781 | commit `312645d8` | Web服务器路径与配置扫描 |

Wapiti约1,900星，未达到本报告的高星门槛。QingScan不满足该门槛，其单独对照见[原始结果](data/20261019/qingscan-upstream-containers.json)。

## 2. 统一口径

- 靶场：本地`vulnerables/web-dvwa:latest`与`bkimminich/juice-shop:latest`容器。
- 起点：每个工具只获得应用根URL，不提供漏洞端点、挑战答案或登录凭据。
- 时间：基准轮每工具每目标计划最多300秒。为补齐完整结果，ZAP随后使用同一镜像和规则、不设主动阶段总时限重跑Juice Shop；主动扫描自然完成至100%，`-m`仍只限制传统爬虫，`-T`仍只限制启动和被动扫描等待。
- Nuclei加载5,299个HTTP模板，排除OAST、DoS、fuzz、爆破、默认口令和token-spray；Nikto使用全部默认插件；ZAP使用固定镜像内置规则；sqlmap使用爬取深度2、表单、`--smart --level=1 --risk=1`。
- 原始告警不能直接互比：Nuclei输出模板匹配，Nikto输出检查项，ZAP输出告警实例，sqlmap输出注入结论。报告只把有HTTP响应证据的结果映射到固定的19项能力观察；同一观察的重复告警合并，相关的3个带参API入口合并为1项“参数入口恢复能力”。
- 19项是竞品在这两个目标上共同贡献的**能力观察并集**，不是19个已标注漏洞，也不是DVWA／Juice Shop挑战总数。

## 3. 结果

| 工具 | 完成情况 | DVWA统一结果（共12项） | Juice Shop统一结果（共7项） | 合计覆盖（共19项） | 请求成本 |
|---|---|---:|---:|---:|---:|
| **Sentinel** | **两目标完整；0错误** | **12/12，另有1项** | **7/7，另有2项** | **19/19（100%），另有3项** | **4,729** |
| Nuclei | 两目标完整 | 5/12 | 3/7 | **8/19（42.1%）** | 18,119 |
| Nikto | 两目标完整 | 6/12 | 4/7 | **10/19（52.6%）** | 17,066 |
| OWASP ZAP | 两目标完整 | 6/12 | 2/7 | **8/19（42.1%）** | Juice Shop主动阶段6,725；完整总数未导出 |
| sqlmap | 两目标完整 | 0/12 | 1/7 | **1/19（5.3%）** | 未导出 |

统一结果均使用同一19项能力观察清单。覆盖项可以在工具之间重叠，因此各行不能相加。sqlmap的1项是“从客户端资产恢复3个带参API入口”这一项能力观察，不表示发现SQL注入。

各工具的“命中”单位不同，原始数字应这样读：

| 工具 | DVWA原始结果 | Juice Shop原始结果 | 合计与解释 |
|---|---:|---:|---|
| Nuclei | 21条模板匹配 | 14条模板匹配 | **35条匹配**；包含INFO资产标签，不等于35个漏洞 |
| Nikto | 14个检查项 | 28个检查项 | **42项**；统一复核后覆盖10项，19项是SPA同体误报，其余为重复、纯信息项或本口径排除项 |
| OWASP ZAP | 12种告警、30个实例 | 4种告警、20个实例 | **50个实例**；两目标均完整，归一后覆盖8项 |
| sqlmap | 1个登录表单，确认注入0 | 3个带参URL，确认注入0 | **确认SQL注入0**；“3”是发现的参数入口，不是3个漏洞 |

因此，Nikto和ZAP的结果不是0。sqlmap只有专项漏洞结论为0，但它仍完成了爬取并从Juice Shop客户端资产恢复3个可测试API入口。原始输出单位不同，所以主表统一使用对19项观察清单的覆盖数比较。

Nikto的42条原始输出经HTTP证据复核、映射到固定观察清单并排除误报与纯信息项后，覆盖并集中的10项：DVWA 6项（`/config`、`/docs`、`/.gitignore`、`/icons/README`、旧Apache版本、安全响应头），Juice Shop 4项（`/ftp`、robots、通配CORS、安全响应头）。10项是覆盖数，包含与Nuclei或ZAP重叠的发现，不表示Nikto独占贡献10项。

Nuclei覆盖8项：DVWA 5项（`/config`、`/.gitignore`、`/README.md`、Cookie、安全响应头），Juice Shop 3项（Swagger、metrics、安全响应头）。ZAP覆盖8项：DVWA 6项（3处目录列表、旧Apache版本、Cookie、安全响应头），Juice Shop 2项（通配CORS、安全响应头）。sqlmap覆盖1项，即Juice Shop的3个带参API入口观察。

这里的“19/19＋3”可按目标拆开理解：

| 靶场 | 竞品经复核并集 | Sentinel复现 | Sentinel额外发现 |
|---|---:|---:|---:|
| DVWA | 12项 | **12/12** | 1项：`/config/config.inc.php.bak`配置备份 |
| OWASP Juice Shop | 7项 | **7/7** | 2项：`/ftp/quarantine`、前端JS中的测试凭据证据 |
| **合计** | **19项** | **19/19** | **3项** |

3项额外发现与官方清单的关系不同：

| Sentinel额外发现 | 官方清单关系 | 本轮证据边界 |
|---|---|---|
| DVWA `/config/config.inc.php.bak` | **不是官方挑战项** | 所测`vulnerables/web-dvwa`旧容器中的部署文件暴露；DVWA官方项目没有Juice Shop式固定挑战计分清单 |
| Juice Shop `/ftp/quarantine` | **不是独立挑战项** | 官方SSTI挑战提示会用到该目录，但SSTI在Docker环境被官方标记为禁用；仅发现目录不等于完成SSTI |
| Juice Shop前端测试凭据 | **对应官方`Exposed Credentials`挑战** | `main.js`公开`testing@juice-sh.op`／`IamUsedForTesting`；另行登录验证返回HTTP 200并获得有效会话 |

因此，“另有3项”表示3项竞品并集之外的有效HTTP发现；其中只有1项可直接映射到当前官方挑战，不能表述为“额外完成3个官方漏洞”。

19项具体包括DVWA的5处目录列表、3份元数据／README、旧Apache、Cookie、安全头和robots，以及Juice Shop的`/ftp`、Swagger、metrics、通配CORS、安全头、3个带参API入口和robots。多个工具会贡献重叠项，因此不能把各工具原始告警数相加当作漏洞数。

Sentinel在DVWA发现26个端点、发送1,851次请求；在Juice Shop发现75个端点和3个参数入口、发送2,878次请求。它把字典枚举、同源JavaScript资产分析、API路由提取、父目录检查及响应语义分类放在一轮扫描中，因此能够复现多个专项工具的互补结果。

## 4. 未计入排名的输出

- Nuclei每个目标的请求计数包含246次被回环安全代理拒绝的非目标请求；数字保留在原始计数中，因此它表示本轮工具总请求成本，不等于全部到达靶场的请求数。
- Nikto在Juice Shop的19项告警都命中相同的9,984字节SPA回退页，确认为软404同体误报，不进入并集。
- Nuclei的`apachegeneric` WAF标签缺少足够证据，不进入并集；单纯技术栈、登录页和现代Web应用标签也不按漏洞计算。
- 本地靶场刻意只开放HTTP，所以HSTS和“HTTP Only Site”提示不进入并集。
- ZAP的传统爬虫在Juice Shop发现116个URL；该应用是SPA，保存的报告也提示Client Spider更适合。首轮在499秒、35%时因时间预算终止；补跑使用相同镜像和规则并自然完成至100%，主动阶段发送6,725次请求。完整报告为4类、20个实例，其中“Modern Web Application”和“User Agent Fuzzer”属于信息项，不进入并集。
- sqlmap的0注入只表示本轮未登录根路径配置没有确认SQL注入，不表示它没有扫描能力。

竞品输出不存在原生的共同覆盖率字段。表中的8/19、10/19、8/19和1/19均来自本报告对原始证据的逐条归一复核；19项由多个竞品互补贡献，Sentinel在同一轮完整扫描中逐项复现。

## 5. 结论边界

这次结果支持“Sentinel在两个本地容器、未登录根路径、固定版本和固定配置下，覆盖经复核竞品并集且请求更少”。它不支持“Sentinel完整规则库超过这些项目”：Nuclei拥有更大的模板生态，ZAP包含浏览器和深度主动规则，sqlmap具有更深入的数据库专项技术。

DVWA和Juice Shop没有在本轮提供完整挑战标签，因此无法计算真实漏洞召回率；安全头、robots和版本信息也不等同于可利用漏洞。当前排名只针对本报告定义的经复核能力观察。

机器可读汇总见[active-scanner-comparison.json](data/20261019/active-scanner-comparison.json)，第三方原始JSON、JSONL和运行日志见[active-scanner-comparison目录](data/20261019/active-scanner-comparison/)，ZAP完整Juice Shop报告见[zap-juice-full.json](data/20261019/active-scanner-comparison/zap-juice-full.json)。
