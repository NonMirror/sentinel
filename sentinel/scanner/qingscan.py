"""QingScan 主动扫描兼容规则。

规则移植自 ``daxia/QingScan`` commit
``2e4706226f1c68121843f37120f05adee57fe80e`` 的 ``app/scan/Dicts.php`` 与
``app/scan/VulnScan.php``。上游 ``composer.json`` 声明 Apache-2.0；这里保留来源，
并将 PHP 数据结构改写为 Sentinel 的 Python 插件/爬虫接口。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExposureRule:
    name: str
    severity: str
    paths: tuple[str, ...]
    keywords: tuple[str, ...]
    vuln_type: str
    description: str
    check_content_type: bool = False
    native_plugin: str = ""


@dataclass(frozen=True, slots=True)
class WafRule:
    headers: tuple[str, ...]
    cookies: tuple[str, ...]
    body: tuple[str, ...]
    firewall: str
    manufacturer: str


# 完整保留 QingScan 的 11 类固定路径规则。已有等价插件的三类由 native_plugin
# 标出，不重复发包；其余规则由 qingscan_exposure 插件执行。
QINGSCAN_EXPOSURE_RULES: tuple[ExposureRule, ...] = (
    ExposureRule("phpinfo 信息泄露", "high",
                 ("/info.php", "/phpinfo.php", "/test.php", "/php_info.php"),
                 ("phpinfo()", "PHP Version"), "phpinfo",
                 "phpinfo 页面泄露 PHP 配置、环境变量与绝对路径",
                 native_plugin="phpinfo"),
    ExposureRule("备份文件泄露", "medium",
                 ("/index.php.bak", "/config.php.bak", "/db.sql", "/backup.zip",
                  "/backup.tar.gz", "/www.zip", "/site.zip", "/web.zip",
                  "/index.html.bak", "/config.old", "/config.bak", "/.bak",
                  "/data.sql"),
                 ("<?php", "mysql", "mysqli", "INSERT INTO", "CREATE TABLE",
                  "DB_HOST", "db_host", "password"),
                 "backup_file", "备份或源码文件可直接下载",
                 check_content_type=True),
    ExposureRule("目录遍历", "high",
                 ("/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                  "/..%2f..%2f..%2fetc%2fpasswd", "/WEB-INF/web.xml",
                  "/..%2f..%2f..%2f..%2fwindows%2fwin.ini"),
                 ("root:", "[fonts]", "web-app"),
                 "path_traversal", "固定路径可读取服务器文件"),
    ExposureRule("Git 配置泄露", "medium", ("/.git/config",),
                 ("[core]", "repositoryformatversion"), "git_leak",
                 ".git/config 暴露源码仓库配置", native_plugin="git_leak"),
    ExposureRule("环境配置泄露", "medium", ("/.env",),
                 ("APP_", "DB_", "SECRET"), "sensitive_config",
                 ".env 暴露应用环境配置"),
    ExposureRule("web.config 泄露", "medium", ("/web.config",),
                 ("<configuration",), "sensitive_config",
                 "web.config 可直接读取"),
    ExposureRule(".htaccess 配置泄露", "medium", ("/.htaccess",),
                 ("RewriteEngine",), "sensitive_config",
                 ".htaccess 可直接读取"),
    ExposureRule("目录配置泄露", "medium", ("/config/",),
                 ("<?php", "DB_", "db_", "password", "database", "define("),
                 "sensitive_config", "/config/ 暴露敏感配置"),
    ExposureRule("Spring Actuator 未授权访问", "high",
                 ("/actuator", "/actuator/env", "/actuator/health"),
                 ('{"status"', "spring", "activeProfiles"), "spring_actuator",
                 "Actuator 未授权暴露", native_plugin="spring_actuator"),
    ExposureRule("Druid 未授权访问", "high",
                 ("/druid/index.html", "/druid"), ("druid", "Druid"),
                 "unauth", "Druid 监控面板未授权访问"),
    ExposureRule("Nacos 未授权访问", "high",
                 ("/nacos/", "/nacos/v1/console/health/liveness"),
                 ("nacos", "Nacos"), "unauth", "Nacos 服务未授权访问"),
)


# QingScan Dicts::dirs()，去掉上游的两个重复项后共 329 项。
QINGSCAN_DIR_PATHS: tuple[str, ...] = tuple(dict.fromkeys("""
admin administrator manage manager management backend system sys index index.php index.html
login login.php login.html logout register user users member members account passport profile
admin/login.php admin/index.php admin/login admin/index admin.php manage/login.php manager/login
api api/ api.php v1 v2 openapi swagger swagger-ui.html swagger/index.html api-docs graphql status
health healthz ping info.php phpinfo.php test.php shell.php cmd.php eval.php phpmyadmin pma myadmin
adminer mysql db phpMyAdmin phpmyadmin/index.php navicat upload uploads file files download downloads
attachment attachments images img image css js static assets public storage media backup backups bak
old temp tmp test tests demo dev develop debug logs log error error.log access.log nginx.conf web.config
.git .git/ .git/config .svn .svn/ .env .env.bak .htaccess .DS_Store .gitignore robots.txt sitemap.xml
sitemap.php crossdomain.xml favicon.ico readme readme.txt README.md readme.md install install/ setup
install.php upgrade update config config/ config.php config.inc.php configuration.php settings setting
wp-admin wp-content wp-includes wp-login.php wp-config.php wordpress wp wp-admin/ wp-content/
wp-includes/ xmlrpc.php wp-json drupal joomla administrator templates modules plugins themes thinkphp
index.php?s= public/index.php application app runtime cache sql data.sql database.sql dump.sql db.sql
backup.sql export export/ import cgi-bin cgi-bin/ perl php-cgi server-status server-info nginx-status
stub_status apache-status webdav dav manager/html manager/status host-manager console dashboard panel
control controlpanel cpanel plesk webmin zabbix zabbix/ grafana grafana/ jenkins jenkins/ gitlab gitlab/
nexus nexus/ kibana kibana/ elasticsearch es redis memcached rabbitmq rabbitmq/ sonar sonarqube artifactory
harbor registry rancher k8s kubernetes prometheus alertmanager consul etcd nacos eureka dubbo sentinel
xxl-job xxl-job-admin seata skywalking zipkin jaeger elastic logstash filebeat metric metrics actuator
actuator/ actuator/health actuator/env actuator/heapdump actuator/mappings actuator/beans vpn sslvpn webvpn
mail webmail owa exchange autodiscover remote rdp vnc teamviewer anydesk sophos fortigate fortinet pfsense
openvpn wireguard ipsec cisco huawei h3c ruijie sharp kuaipan baidu yun oss cos bucket object minio s3
storage/ oss/ cos/ upload/ uploads/ file/ files/ doc/ docs/ wiki wiki/ confluence jira jira/ fogbugz
trac redmine mantis bugzilla phpmyadmin/ weblogic websphere jboss tomcat tomcat/ catalina jsp-examples
servlet-examples manager host-manager/ webdav/ axis axis2 struts struts2 spring springboot druid druid/
druid/index.html swagger-ui v2/api-docs v3/api-docs openapi.json actuator/gateway nacos/ nacos/v1 eureka/
apollo apollo/ xxljob ddos shell hack hacker hackme toy waf waf/
""".split()))


# (名称, 请求头条件, 正文关键词)。同一规则任一条件命中即识别，与 QingScan 一致。
QINGSCAN_FINGERPRINTS: tuple[
    tuple[str, tuple[tuple[str, str], ...], tuple[str, ...]], ...
] = (
    ("nginx", (("server", "nginx"),), ()),
    ("apache", (("server", "apache"),), ()),
    ("IIS", (("server", "iis"),), ()),
    ("tomcat", (("server", "tomcat"),), ("tomcat",)),
    ("jetty", (("server", "jetty"),), ()),
    ("openresty", (("server", "openresty"),), ()),
    ("PHP", (("x-powered-by", "php"),), ("php",)),
    ("ASP.NET", (("x-powered-by", "asp.net"), ("x-aspnet-version", "")),
     ("__viewstate", "asp.net")),
    ("Java", (("x-powered-by", "java"),), ("java.servlet", "jsp")),
    ("thinkphp", (), ("thinkphp", "tp5", "think\\")),
    ("laravel", (), ("laravel", "csrf-token")),
    ("wordpress", (), ("wp-content", "wp-includes", "wordpress")),
    ("drupal", (), ("drupal", "drupal.settings")),
    ("joomla", (), ("joomla", "com_content")),
    ("discuz", (), ("discuz", "powered by discuz")),
    ("phpwind", (), ("phpwind",)),
    ("dedecms", (), ("dedecms", "powered by dedecms")),
    ("帝国CMS", (), ("ecms", "empirecms")),
    ("织梦CMS", (), ("dedecms",)),
    ("phpMyAdmin", (), ("phpmyadmin", "pma_theme", "pma_logout")),
    ("Jenkins", (), ("jenkins", "jenkins-ci.org")),
    ("GitLab", (), ("gitlab", "gitlab-logo")),
    ("Grafana", (), ("grafana", "grafana-app")),
    ("Zabbix", (), ("zabbix", "zabbix.js")),
    ("SonarQube", (), ("sonarqube", "sonar")),
    ("Kibana", (), ("kibana",)),
    ("Elasticsearch", (), ("elasticsearch",)),
    ("Swagger", (), ("swagger-ui", "swagger")),
    ("Druid", (), ("druid", "druid-console")),
    ("Nacos", (), ("nacos",)),
    ("XXL-JOB", (), ("xxl-job",)),
    ("Django", (("server", "django"), ("x-frame-options", "deny")), ("django",)),
    ("Flask", (("server", "werkzeug"),), ()),
    ("Node.js", (("x-powered-by", "express"),), ("node.js",)),
    ("Shiro", (("set-cookie", "rememberme"),), ()),
    ("Spring", (), ("spring", "whitelabel error")),
    ("Shiro权限框架", (), ("shiro",)),
    ("fastjson", (), ("fastjson",)),
    ("log4j", (), ("log4j",)),
    ("WebLogic", (("server", "weblogic"),), ("weblogic",)),
    ("WebSphere", (("server", "websphere"),), ()),
    ("JBoss", (("server", "jboss"),), ("jboss",)),
    ("Struts2", (), ("struts2", "org.apache.struts")),
    ("RabbitMQ", (), ("rabbitmq",)),
    ("Redis", (), ("redis",)),
    ("Memcached", (), ("memcached",)),
    ("MinIO", (), ("minio",)),
    ("Harbor", (), ("harbor",)),
    ("Nexus", (), ("nexus",)),
    ("ALIBABA", (), ("alibaba",)),
    ("Bootstrap", (), ("bootstrap",)),
    ("jQuery", (), ("jquery",)),
    ("Vue.js", (), ("vue.js", 'id="app"')),
    ("React", (), ("react", "__nxtg")),
    ("Angular", (), ("angular",)),
)


QINGSCAN_WAF_RULES: tuple[WafRule, ...] = (
    WafRule(("x-waf",), (), (), "aliyun", "阿里云盾"),
    WafRule(("x-powered-by-anquanbao",), (), (), "anquanbao", "安全宝"),
    WafRule(("x-cdn",), (), (), "ChinaCache", "加速乐"),
    WafRule(("server:sucuri",), (), (), "Sucuri", "Sucuri"),
    WafRule(("x-iss-waf",), (), (), "ISSWAF", "艾赛"),
    WafRule(("x-ds-waf",), (), (), "DS-WAF", "盾"),
    WafRule(("x-safedog",), (), (), "safedog", "安全狗"),
    WafRule((), ("yunwaf",), (), "yunsuo", "云锁"),
    WafRule((), ("__jsluid_s",), (), "ChinaCache", "加速乐"),
    WafRule((), ("cfduid",), (), "Cloudflare", "Cloudflare"),
    WafRule((), ("safedog",), (), "safedog", "安全狗"),
    WafRule((), ("__cdid",), (), "ChinaCache", "加速乐"),
    WafRule((), ("_waf",), (), "unknown", "通用WAF"),
    WafRule((), ("ns_af",), (), "ChinaNetCenter", "网宿"),
    WafRule((), ("yd_cookie",), (), "aliyun", "云盾"),
    WafRule((), (), ("mod_security",), "ModSecurity", "ModSecurity"),
    WafRule((), (), ("360wzws",), "360", "360网站卫士"),
    WafRule((), (), ("safedog",), "safedog", "安全狗"),
    WafRule((), (), ("yundun",), "aliyun", "阿里云盾"),
    WafRule((), (), ("wangzhan.360",), "360", "360"),
    WafRule((), (), ("web application firewall",), "unknown", "通用WAF"),
    WafRule((), (), ("__jsl",), "ChinaCache", "加速乐"),
)


def detect_qingscan_fingerprints(headers: dict[str, str], body: str) -> list[str]:
    """按 QingScan FingerScan 的任一条件命中语义识别技术栈。"""
    lowered = {key.lower(): value.lower() for key, value in headers.items()}
    preview = body[:2000].lower()
    found: list[str] = []
    for name, header_rules, body_rules in QINGSCAN_FINGERPRINTS:
        header_hit = any(key in lowered and (not value or value in lowered[key])
                         for key, value in header_rules)
        if header_hit or any(pattern.lower() in preview for pattern in body_rules):
            found.append(name)
    return found


__all__ = ["ExposureRule", "WafRule", "QINGSCAN_DIR_PATHS",
           "QINGSCAN_EXPOSURE_RULES", "QINGSCAN_FINGERPRINTS", "QINGSCAN_WAF_RULES",
           "detect_qingscan_fingerprints"]
