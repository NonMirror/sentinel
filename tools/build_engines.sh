#!/usr/bin/env bash
# 构建**可选的参考数据面**: 真实 nginx + libmodsecurity + Naxsi.
#
#   yajl 2.1.0        (ModSecurity 的 JSON 解析依赖, cmake)
#   ModSecurity v3    (owasp-modsecurity/ModSecurity, C++ 引擎)
#   nginx 1.22.1      + modsecurity-nginx + naxsi 静态模块
#
# 产物落在 **sentinel 自己的构建目录**: $SENTINEL_BUILD_ROOT (默认 sentinel/build)
#   -> sentinel/build/nginx-sentinel/sbin/nginx
#      sentinel.waf.engines.nginx_stack.NginxInstall 会自动发现它
#
# 源码从 $SENTINEL_WAF_SRC 读取 (默认 ../waf_pro)。这只是**构建期的**上游源码
# 来源; 运行时的规则数据全部来自 sentinel/vendor, 编译好后即使删掉源码目录,
# 参考引擎依然可用。
#
# 注意: 不构建也完全不影响 Sentinel —— 原生解释器不需要任何 C 工具链。
# 这一层存在的意义是**校对原生解释器的语义** (同一套 CRS 规则, 两种实现对比)。
#
# 用法:  tools/build_engines.sh [--force]
set -euo pipefail

SENTINEL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAF_SRC="${SENTINEL_WAF_SRC:-${SENTINEL_WAF_ROOT:-$SENTINEL_ROOT/../waf_pro}}"
BUILD_ROOT="${SENTINEL_BUILD_ROOT:-$SENTINEL_ROOT/build}"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

BUILD="$BUILD_ROOT/_build"             # 中间产物
PREFIX="$BUILD_ROOT/_prefix"           # yajl 安装前缀
MODSEC="$BUILD_ROOT/_modsecurity"      # libmodsecurity 安装前缀
NGINX_PREFIX="$BUILD_ROOT/nginx-sentinel"
JOBS="$(nproc 2>/dev/null || echo 4)"

log() { printf '\033[38;5;109m[build]\033[0m %s\n' "$*"; }
die() { printf '\033[38;5;210m[build] %s\033[0m\n' "$*" >&2; exit 1; }

[[ -d "$WAF_SRC" ]] || die "未找到上游源码目录: $WAF_SRC (用 SENTINEL_WAF_SRC 指定)"
mkdir -p "$BUILD" "$PREFIX" "$BUILD_ROOT"

# ---------------------------------------------------------------- yajl
if [[ $FORCE -eq 1 || ! -e "$PREFIX/lib/libyajl.so" ]]; then
    log "构建 yajl 2.1.0 -> $PREFIX"
    cmake -S "$WAF_SRC/yajl" -B "$BUILD/yajl" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON >/dev/null
    cmake --build "$BUILD/yajl" -j "$JOBS" >/dev/null
    cmake --install "$BUILD/yajl" >/dev/null
else
    log "yajl 已就绪, 跳过"
fi

# ---------------------------------------------------------------- ModSecurity
if [[ $FORCE -eq 1 || ! -e "$MODSEC/lib/libmodsecurity.so" ]]; then
    log "构建 libmodsecurity v3 -> $MODSEC"
    ( cd "$WAF_SRC/modsecurity"
      sh ./build.sh
      ./configure --prefix="$MODSEC" --with-yajl="$PREFIX" \
                  --disable-examples --disable-doxygen-dot --disable-doxygen-html
      make -j "$JOBS"
      make install )
else
    log "libmodsecurity 已就绪, 跳过"
fi

# ---------------------------------------------------------------- nginx
if [[ $FORCE -eq 1 || ! -x "$NGINX_PREFIX/sbin/nginx" ]]; then
    log "配置并编译 nginx 1.22.1 + modsecurity-nginx + naxsi"
    NGINX_SRC="$WAF_SRC/nginx"
    if [[ ! -d "$NGINX_SRC" ]]; then
        [[ -f "$WAF_SRC/dl/nginx-1.22.1.tar.gz" ]] || \
            die "缺少 nginx 源码: $NGINX_SRC 或 $WAF_SRC/dl/nginx-1.22.1.tar.gz"
        tar -xzf "$WAF_SRC/dl/nginx-1.22.1.tar.gz" -C "$WAF_SRC"
    fi
    ( cd "$NGINX_SRC"
      ./configure \
          --prefix="$NGINX_PREFIX" \
          --without-pcre2 \
          --with-cc-opt=-Wno-error \
          --with-http_stub_status_module \
          --with-http_realip_module \
          --with-http_ssl_module \
          --with-threads \
          --with-ld-opt="-L$MODSEC/lib -L$PREFIX/lib -Wl,-rpath,$PREFIX/lib" \
          --add-module="$WAF_SRC/naxsi/naxsi_src" \
          --add-module="$WAF_SRC/modsecurity-nginx"
      make -j "$JOBS"
      make install )
else
    log "nginx 已就绪, 跳过 (--force 可强制重建)"
fi

log "自检: $("$NGINX_PREFIX/sbin/nginx" -V 2>&1 | head -1)"
log "完成. 参考引擎现在可用:"
log "  :engine nginx-modsecurity   /   :engine nginx-naxsi"
