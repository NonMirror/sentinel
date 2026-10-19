# 测试结果

## WAF

- 攻击样本：Wallarm GoTestWAF * 434
- 正常请求：GoTestWAF * 94、自编 * 75、CSIC 2010 * 10000

做对照实验，与以下项目进行对比

| 项目                                                         |    GitHub星数 |      |      |
| :----------------------------------------------------------- | ------------: | ---- | ---- |
| [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) + [OWASP CRS](https://github.com/coreruleset/coreruleset) | 9,811 + 3,307 |      |      |
| [NAXSI](https://github.com/nbs-system/naxsi)                 |         4,804 |      |      |
| [Coraza](https://github.com/corazawaf/coraza) + [OWASP CRS](https://github.com/coreruleset/coreruleset) | 3,910 + 3,307 |      |      |

### 实验结果

| 实现／配置                |            总体拦截 | 类别等权拦截 |    169条良性误报 | CSIC 10,000条留出误报 |
| ------------------------- | ------------------: | -----------: | ---------------: | --------------------: |
| **Sentinel balanced PL4** | **414/434，95.39%** |   **95.15%** | **5/169，2.96%** | **508/10,000，5.08%** |
| ModSecurity PL1           |     342/434，78.80% |       72.77% |   20/169，11.83% |     486/10,000，4.86% |
| Coraza PL1                |     342/434，78.80% |       72.77% |   20/169，11.83% |     486/10,000，4.86% |
| NAXSI 1.3 基准阈值档      |     410/434，94.47% |       88.78% |   61/169，36.09% |  1,491/10,000，14.91% |
| ModSecurity PL4           |     432/434，99.54% |       98.94% |  132/169，78.11% |   10,000/10,000，100% |
| Coraza PL4                |     433/434，99.77% |       99.47% |  143/169，84.62% |   10,000/10,000，100% |

## 扫描器

- DVWA
- OWASP Juice Shop

| 项目                                                 | GitHub星数 | 定位                          |
| ---------------------------------------------------- | ---------: | ----------------------------- |
| [sqlmap](https://github.com/sqlmapproject/sqlmap)    |     38,734 | SQL注入专项，带爬虫和表单解析 |
| [Nuclei](https://github.com/projectdiscovery/nuclei) |     32,121 | 大规模模板扫描                |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy)      |     15,964 | 爬虫、被动规则和主动DAST      |
| [Nikto](https://github.com/sullo/nikto)              |     10,781 | Web服务器固定路径与配置扫描   |

配置：

- Nuclei：加载5,299个签名HTTP模板；排除OAST、DoS、fuzz、爆破、默认口令和token-spray。
- Nikto：全部默认插件。
- ZAP：传统爬虫、固定镜像内置被动／主动规则；在线插件更新会阻塞启动，因此用`-silent`固定规则集。
- sqlmap：爬取深度2、表单、`--smart --level=1 --risk=1`。

### 实验结果

| 工具         | 两目标完成情况                      | 结果        |
| ------------ | ----------------------------------- | ----------- |
| **Sentinel** | **均完整**                          | 13+9=**22** |
| Nuclei       | 均完整                              | 5+3=8       |
| Nikto        | 均完整                              | 6+4=10      |
| OWASP ZAP    | DVWA完整；Juice Shop 35%（timeout） | 6+2=8       |
| sqlmap       | 均完整                              | 0+1=1       |
