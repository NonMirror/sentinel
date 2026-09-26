"""Sentinel — 可视化安全运营与管理平台.

**Sentinel 是自包含的**: 规则语言、扫描模板、判定引擎全部是本仓自己的代码与
数据, 运行时不读取任何同级工程目录, 也不需要外部二进制。

======================  ==================================================
子系统                   实现
======================  ==================================================
轻量级防火墙             :mod:`sentinel.waf` —— 自研 SecRule 解释器执行 OWASP CRS;
                        自研 Naxsi 评分器; 内置轻量规则集
漏洞扫描子系统           :mod:`sentinel.scanner` —— 自研 nuclei 模板解释器执行
                        官方模板; 自研插件式主动扫描; 内置检测器
可视化安全运营平台       :mod:`sentinel.tui` —— Textual + Catppuccin Frappé
后端 WEB 漏洞靶场        :mod:`sentinel.lab` —— 多实例, 预置十类漏洞
内置第三方数据           :mod:`sentinel.vendor` —— 由 ``tools/vendor.py`` 收敛
======================  ==================================================

模块划分对应架构图:
    综设I  漏洞扫描子系统 -> sentinel.scanner
    综设II 轻量级防火墙   -> sentinel.waf
    综设III 可视化安全运营与管理平台 -> sentinel.tui
    后端WEB服务 漏洞靶场 -> sentinel.lab
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
