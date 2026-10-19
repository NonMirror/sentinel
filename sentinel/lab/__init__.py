"""后端WEB服务 漏洞靶场 (多实例), 供 WAF 保护与扫描器靶场验证."""
from .flags import FLAGS, VULN_NAMES, all_flags, flag
from .server import LabApp, LabServer, start_lab, start_lab_fleet

__all__ = ["LabApp", "LabServer", "start_lab", "start_lab_fleet",
           "FLAGS", "VULN_NAMES", "flag", "all_flags"]
