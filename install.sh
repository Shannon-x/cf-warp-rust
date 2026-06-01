#!/usr/bin/env bash
# warp-rust install.sh  schema=7  (auto interactive by default, /dev/tty 局部重定向，curl|bash 也能交互)
#
# warp-rust 一键安装 / 卸载 / 更新脚本（Linux + systemd 专用）
#
# === 推荐用法（一行命令）===
#   curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh | sudo bash
#
# === 带参数 ===
#   curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
#     | sudo bash -s -- --port 1080 --expose
#
# === 卸载 ===
#   curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
#     | sudo bash -s -- --uninstall
#
# === 更新到最新版（保留配置）===
#   curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
#     | sudo bash -s -- --update
#
# === 选项 ===
#   --port PORT       SOCKS5 监听端口（默认 1080）
#   --expose          绑 0.0.0.0 对外（必须有强密码；不传 --pass 则自动生成）
#   --user USER       SOCKS5 用户名（默认 warp）
#   --pass PASS       SOCKS5 密码（≥16 位含大小写+数字；--expose 时必填或自动生成）
#   --version vX.Y.Z  指定版本（默认 latest）
#   --uninstall       卸载（保留 /etc/warp-rust 和 /var/lib/warp-rust）
#   --update          更新二进制到最新版本，不动配置
#   --status          查看服务状态后退出
#   -h, --help        显示此帮助

set -euo pipefail

REPO="Shannon-x/cf-warp-rust"

# GitHub 代理镜像列表（国内连 github.com 慢时自动 fallback）
# 用法：
#   GH_PROXY="https://ghproxy.com/" curl ... | sudo bash      # 显式指定
#   GH_PROXY="" curl ... | sudo bash                          # 强制直连 GitHub
# 默认按顺序尝试：直连 → ghproxy.com → ghproxy.cn → ghp.ci
# 任一可达就用它，全失败才报错
GH_PROXIES_DEFAULT=(
  ""                              # 先试直连
  "https://ghproxy.net/"
  "https://mirror.ghproxy.com/"
  "https://ghproxy.cn/"
  "https://gh.api.99988866.xyz/"
)
if [ -n "${GH_PROXY+x}" ]; then
  # 用户显式设了 GH_PROXY（即使是空串），只用这一个值
  GH_PROXIES=("$GH_PROXY")
else
  GH_PROXIES=("${GH_PROXIES_DEFAULT[@]}")
fi

INSTALL_BIN="/usr/local/bin/warp-rust"
CONF_DIR="/etc/warp-rust"
CONF_FILE="${CONF_DIR}/config.toml"
DATA_DIR="/var/lib/warp-rust"
SERVICE_NAME="warp-rust"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="warp-rust"

# ── 输出工具 ─────────────────────────────────────────────────────────────────
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
die()  { echo "${RED}✗ $*${RESET}" >&2; exit 1; }
info() { echo "${CYAN}▸${RESET} $*"; }
warn() { echo "${YELLOW}!${RESET} $*"; }
ok()   { echo "${GREEN}✓${RESET} $*"; }

# ── 前置检查 ─────────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || die "请用 root（sudo bash 或直接 root shell）运行"

for cmd in curl tar systemctl install id; do
  command -v "$cmd" >/dev/null || die "缺依赖：$cmd"
done

if ! command -v sha256sum >/dev/null && ! command -v shasum >/dev/null; then
  die "缺 sha256 工具：请装 coreutils 或 perl"
fi

# 系统/架构
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$os" = "linux" ] || die "本脚本仅支持 Linux；其他平台请从 Release 下载二进制手动部署"

case "$(uname -m)" in
  x86_64|amd64)  TARGET="x86_64-unknown-linux-musl" ;;
  aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
  *) die "不支持的架构：$(uname -m)（仅 x86_64 / aarch64）" ;;
esac

# ── 解析参数 ─────────────────────────────────────────────────────────────────
PORT=""
EXPOSE=""
USER_NAME=""
PASS=""
VERSION=""
ACTION="install"
# v0.2.3 / schema=7：默认 auto —— /dev/tty 可达就交互，cron/CI 自动走默认非交互
# (auto | yes | no)
INTERACTIVE_MODE="auto"
# 是否传入了任何 install 参数；传了就强制非交互，免得 curl|bash --port 8964 还问一遍
EXPLICIT_INSTALL_ARG=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port)              PORT="${2:?}"; shift; EXPLICIT_INSTALL_ARG=1 ;;
    --expose)            EXPOSE=1; EXPLICIT_INSTALL_ARG=1 ;;
    --no-expose)         EXPOSE=0; EXPLICIT_INSTALL_ARG=1 ;;
    --user)              USER_NAME="${2:?}"; shift; EXPLICIT_INSTALL_ARG=1 ;;
    --pass)              PASS="${2:?}"; shift; EXPLICIT_INSTALL_ARG=1 ;;
    --version)           VERSION="${2:?}"; shift ;;
    --interactive|-i)    INTERACTIVE_MODE="yes" ;;
    --yes|-y)            INTERACTIVE_MODE="no" ;;
    --noninteractive)    INTERACTIVE_MODE="no" ;;
    --uninstall)         ACTION="uninstall" ;;
    --update)            ACTION="update" ;;
    --status)            ACTION="status" ;;
    -h|--help)           sed -n '2,46p' "$0" 2>/dev/null; exit 0 ;;
    *) die "未知参数：$1（用 --help 看帮助）" ;;
  esac
  shift
done

# 探测 /dev/tty 是否可读 —— curl|bash 时 stdin 是 pipe，但 /dev/tty 通常仍指向
# 真实终端；只有 cron、systemd run、纯无 tty 容器才会探不到。
tty_reachable() {
  [ -r /dev/tty ] && [ -w /dev/tty ]
}

# 决定最终是否进交互
final_interactive=0
if [ "$ACTION" = "install" ]; then
  case "$INTERACTIVE_MODE" in
    yes)
      if tty_reachable; then
        final_interactive=1
      else
        warn "-i 启用但 /dev/tty 不可达（cron/CI/纯容器环境？），回退非交互默认"
        final_interactive=0
      fi
      ;;
    no)
      final_interactive=0
      ;;
    auto)
      # 没传任何 install 参数 + tty 可达 → 自动交互
      if [ "$EXPLICIT_INSTALL_ARG" = 0 ] && tty_reachable; then
        final_interactive=1
      else
        final_interactive=0
      fi
      ;;
  esac
fi
INTERACTIVE="$final_interactive"

if [ "$ACTION" = "install" ] && [ "$INTERACTIVE" = 1 ]; then
  echo
  echo "${BOLD}════════════════════════════════════════════════════════${RESET}"
  echo "${BOLD}  warp-rust 安装向导${RESET}"
  echo "${BOLD}════════════════════════════════════════════════════════${RESET}"
  echo
  echo "  · 仅本机访问（127.0.0.1）${BOLD}不需要${RESET}密码"
  echo "  · 对外暴露（0.0.0.0）会${BOLD}强制${RESET}启用强密码鉴权"
  echo

  # 关键：用局部 `< /dev/tty` 重定向，而非 exec </dev/tty
  # 局部模式只影响这一次 read，更稳健、ssh+sudo+curl|bash 大多数环境都通

  while :; do
    read -r -p "  SOCKS5 监听端口 [1080]: " ans < /dev/tty || ans=""
    PORT="${ans:-1080}"
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] && break
    warn "端口非法，请输入 1-65535"
  done

  while :; do
    echo
    echo "  绑定范围：L=仅本机 127.0.0.1（推荐）  E=对外 0.0.0.0（强制密码）"
    read -r -p "  选择 [L/e]: " ans < /dev/tty || ans="L"
    case "${ans:-L}" in
      L|l|"")        EXPOSE=0; break ;;
      E|e|external)  EXPOSE=1; break ;;
      *) warn "请输入 L 或 E" ;;
    esac
  done

  if [ "$EXPOSE" = 1 ]; then
    echo
    read -r -p "  SOCKS5 用户名 [warp]: " ans < /dev/tty || ans=""
    USER_NAME="${ans:-warp}"
    while :; do
      echo "  密码：直接回车 = 自动生成 24 位；或手输 ≥16 位含大小写+数字"
      read -r -s -p "  密码: " pw < /dev/tty || pw=""
      echo
      if [ -z "$pw" ]; then PASS=""; break; fi
      if [ "${#pw}" -ge 16 ] && [[ "$pw" =~ [A-Z] ]] && [[ "$pw" =~ [a-z] ]] && [[ "$pw" =~ [0-9] ]]; then
        PASS="$pw"; break
      fi
      warn "密码强度不够，请重输"
    done
  fi
  echo
fi

# 默认值（非交互或交互未指定时）
[ -z "$PORT" ] && PORT=1080
[ -z "$EXPOSE" ] && EXPOSE=0
[ -z "$USER_NAME" ] && USER_NAME="warp"

[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
  || die "端口非法：$PORT"

# ── 交互完后立刻显示配置摘要，让用户知道脚本继续走 ─────────────────────────
if [ "$ACTION" = "install" ]; then
  echo "${BOLD}配置摘要：${RESET}"
  if [ "$EXPOSE" = 1 ]; then
    echo "  绑定地址 : ${BOLD}0.0.0.0:$PORT${RESET}（对外暴露）"
    echo "  鉴权     : 用户名 ${BOLD}$USER_NAME${RESET}，密码 ${BOLD}$([ -n "$PASS" ] && echo '已指定' || echo '自动生成')${RESET}"
  else
    echo "  绑定地址 : ${BOLD}127.0.0.1:$PORT${RESET}（仅本机）"
    echo "  鉴权     : 无（loopback only）"
  fi
  echo "  架构     : $TARGET"
  echo
  info "接下来会自动执行：查询版本 → 下载二进制 → 校验 → 安装 → 启动服务"
  info "全程约 15-30 秒（首次启动时会注册 WARP 账号，需要约 5 秒）"
  echo
fi

# ── 工具函数 ─────────────────────────────────────────────────────────────────
gen_pw() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 36 | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 24
  else
    head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 24
  fi
}
ok_pw() {
  local p="$1"
  [ "${#p}" -ge 16 ] && [[ "$p" =~ [A-Z] ]] && [[ "$p" =~ [a-z] ]] && [[ "$p" =~ [0-9] ]]
}
# 通用 fetch：按 GH_PROXIES 列表挨个试，先成功的赢。
# 用法：gh_fetch <output_file> <relative_url_to_github>
#   gh_fetch /tmp/file.tgz "https://github.com/owner/repo/releases/download/v1/x.tgz"
# 也支持 api.github.com（同样会被代理）
gh_fetch() {
  local out="$1" url="$2"
  local proxy effective code
  for proxy in "${GH_PROXIES[@]}"; do
    if [ -n "$proxy" ]; then
      effective="${proxy%/}/${url}"
    else
      effective="$url"
    fi
    # 静默尝试，10 秒连接 + 60 秒总；成功则退出
    code="$(curl -fsSL -o "$out" -w '%{http_code}' \
              --connect-timeout 10 --max-time 60 \
              "$effective" 2>/dev/null || echo "000")"
    if [ "$code" = "200" ] && [ -s "$out" ]; then
      [ -n "$proxy" ] && info "  (via 代理 ${proxy})"
      return 0
    fi
    [ -n "$proxy" ] && warn "  代理 ${proxy} 失败（code=$code），尝试下一个..."
  done
  return 1
}

# 大文件下载版（同 gh_fetch，但带进度条）
gh_download() {
  local out="$1" url="$2"
  local proxy effective
  for proxy in "${GH_PROXIES[@]}"; do
    if [ -n "$proxy" ]; then
      effective="${proxy%/}/${url}"
      info "  尝试代理：${proxy}"
    else
      effective="$url"
      info "  尝试直连 GitHub"
    fi
    if curl -fSL --progress-bar \
            --connect-timeout 15 --max-time 300 \
            "$effective" -o "$out" 2>&1; then
      return 0
    fi
    warn "  失败，换下一个源..."
  done
  return 1
}

verify_sha256() {
  # 不用 `sha256sum -c`（它会按 sha 文件里写的路径去找文件，路径前缀就会出错）。
  # 直接抽出 sha 文件里的 hash 跟实际文件的 hash 对比 —— 无论 sha 文件里
  # 写的是 `file`、`dist/file`、`./xxx/file` 都不影响。
  local sha_file="$1" target_file="$2"
  local expected actual
  expected="$(awk 'NR==1 {print tolower($1)}' "$sha_file")"
  if [ -z "$expected" ] || [ "${#expected}" -ne 64 ]; then
    echo "sha256 文件格式异常：$(head -1 "$sha_file")" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$target_file" | awk '{print tolower($1)}')"
  else
    actual="$(shasum -a 256 "$target_file" | awk '{print tolower($1)}')"
  fi
  if [ "$expected" = "$actual" ]; then
    echo "$target_file: OK"
    return 0
  else
    echo "sha256 不匹配" >&2
    echo "  expected: $expected" >&2
    echo "  actual  : $actual" >&2
    return 1
  fi
}

# ── 操作：status ────────────────────────────────────────────────────────────
if [ "$ACTION" = "status" ]; then
  systemctl status "$SERVICE_NAME" --no-pager 2>&1 || true
  echo
  ss -tlnp 2>/dev/null | grep -E "warp-rust|:1080|:9090" || true
  exit 0
fi

# ── 操作：uninstall ─────────────────────────────────────────────────────────
if [ "$ACTION" = "uninstall" ]; then
  info "停止并禁用服务..."
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$INSTALL_BIN"
  systemctl daemon-reload
  echo
  warn "保留以下目录（含 WARP 凭据，删除后下次启动需重新注册）："
  echo "    $CONF_DIR"
  echo "    $DATA_DIR"
  echo "  彻底清理执行： ${BOLD}sudo rm -rf $CONF_DIR $DATA_DIR${RESET}"
  echo "  删系统用户：    ${BOLD}sudo userdel $SERVICE_USER${RESET}"
  ok "warp-rust 已卸载"
  exit 0
fi

# ── 解析最新版本号 ───────────────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
  info "[1/5] 查询 GitHub 最新 release"
  TMP_API="$(mktemp)"
  if gh_fetch "$TMP_API" "https://api.github.com/repos/${REPO}/releases/latest"; then
    VERSION="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP_API" | head -1)"
  fi
  rm -f "$TMP_API"
  if [ -z "$VERSION" ]; then
    warn "所有源都获取不到最新版本号"
    echo "  → 加 --version v0.1.0 跳过 API 查询：" >&2
    echo "    curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s -- --version v0.1.0" >&2
    die "无法获取最新版本号"
  fi
  ok "最新版本：${BOLD}$VERSION${RESET}"
else
  info "[1/5] 使用指定版本：${BOLD}$VERSION${RESET}"
fi

# ── 下载 + 校验 ─────────────────────────────────────────────────────────────
ASSET="warp-rust-${VERSION}-${TARGET}.tar.gz"
URL_TGZ="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
URL_SHA="${URL_TGZ}.sha256"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "[2/5] 下载 ${ASSET}（约 4 MB）"
gh_download "$TMP/$ASSET" "$URL_TGZ" \
  || die "下载失败（所有源都不通；可手动 wget 后用 --version 跳过）"
gh_fetch "$TMP/$ASSET.sha256" "$URL_SHA" \
  || die "下载 sha256 失败"

info "[3/5] 校验 sha256..."
verify_sha256 "$TMP/$ASSET.sha256" "$TMP/$ASSET" >/dev/null \
  || die "sha256 校验失败 —— 文件可能损坏或被篡改"
ok "sha256 校验通过"

info "[4/5] 解压并安装到系统..."
tar xzf "$TMP/$ASSET" -C "$TMP"
EXTRACTED="$TMP/warp-rust-${VERSION}-${TARGET}"
[ -x "$EXTRACTED/warp-rust" ] || die "解压后未找到 warp-rust 可执行文件"

# ── 操作：update（仅替换二进制，不动配置/数据/服务文件）────────────────────
if [ "$ACTION" = "update" ]; then
  [ -f "$SERVICE_FILE" ] || die "未检测到已安装的 warp-rust（找不到 $SERVICE_FILE）。请改用全新安装"

  info "停止服务以替换二进制..."
  systemctl stop "$SERVICE_NAME"
  install -m 0755 -o root -g root "$EXTRACTED/warp-rust" "$INSTALL_BIN"
  ok "二进制已更新到 ${VERSION}"
  systemctl start "$SERVICE_NAME"
  sleep 1
  systemctl is-active --quiet "$SERVICE_NAME" \
    && ok "服务已重启" \
    || warn "服务启动失败，请用 journalctl -u $SERVICE_NAME -n 50 查看"
  exit 0
fi

# ── 操作：install ───────────────────────────────────────────────────────────
# 系统用户
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  echo "  · 创建系统用户 $SERVICE_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
    || adduser --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
  echo "  · 系统用户 $SERVICE_USER 已存在"
fi

echo "  · 安装二进制到 $INSTALL_BIN"
install -m 0755 -o root -g root "$EXTRACTED/warp-rust" "$INSTALL_BIN"

echo "  · 创建目录 $CONF_DIR / $DATA_DIR"
install -m 0755 -d "$CONF_DIR"
install -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" -d "$DATA_DIR"

# ── 鉴权 / 绑定决策 ─────────────────────────────────────────────────────────
if [ "$EXPOSE" = 1 ]; then
  BIND="0.0.0.0:$PORT"
  if [ -z "$PASS" ]; then
    PASS="$(gen_pw)"
    ok "自动生成 SOCKS5 密码：${BOLD}$PASS${RESET}"
    warn "立即妥善保存（脚本不会再次显示；也会写入 $CONF_FILE 权限 0640）"
  fi
  ok_pw "$PASS" || die "密码强度不够（≥16 位，含大写+小写+数字）"
else
  BIND="127.0.0.1:$PORT"
fi

# ── 写配置 ──────────────────────────────────────────────────────────────────
echo "  · 生成配置 $CONF_FILE"
{
  echo "# 由 install.sh 自动生成"
  echo "# 重新跑 install.sh 会覆盖；要保留请改名再启动 systemd 自定义 unit"
  echo
  echo "[server]"
  echo "bind = \"$BIND\""
  if [ "$EXPOSE" = 1 ]; then
    echo
    echo "[server.auth]"
    printf 'username = "%s"\n' "$USER_NAME"
    printf 'password = "%s"\n' "$PASS"
  fi
  cat <<EOF

[logging]
# 第三方依赖（wireguard_netstack 等）默认只打 warn 以上，
# 自己模块 warp_rust 保持 info；这样正常运行几乎无日志，
# 只有异常或自愈动作才会落 journald，一个月日志通常 <10MB
level = "warn,warp_rust=info"
format = "compact"

[warp]
data_dir = "$DATA_DIR"
device_model = "warp-rust"
refresh_interval = "24h"
register_cooldown = "10m"

[health]
interval = "30s"
timeout = "8s"

[recovery]
reconnect_after = 1
rebuild_config_after = 3
reregister_after = 5
rotate_identity_after = 10
backoff_min = "500ms"
backoff_max = "30s"

[metrics]
enabled = true
bind = "127.0.0.1:9090"

[hot_reload]
enabled = false
EOF
} > "$CONF_FILE"
chown root:"$SERVICE_USER" "$CONF_FILE"
chmod 0640 "$CONF_FILE"

# ── 写 systemd unit ─────────────────────────────────────────────────────────
echo "  · 写 systemd unit $SERVICE_FILE"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=warp-rust SOCKS5 proxy through Cloudflare WARP
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_BIN --config $CONF_FILE
WorkingDirectory=$DATA_DIR
Restart=always
RestartSec=5
LimitNOFILE=65535

# 日志：走 systemd-journald（journalctl -u $SERVICE_NAME）
# journald 自带 rotation（默认上限磁盘 10% 或 4GB）；这里再加 rate-limit
# 防异常时日志洪水把 journald 自身刷爆
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=500

# 安全加固（systemd sandboxing）
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "[4/5] 安装完成"

info "[5/5] 启动 systemd 服务，等服务真正可用..."
systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1 || true

# 跟实时日志最多 25 秒，看到 'SOCKS5 listening' 就算成功
echo
echo "${CYAN}── 服务启动日志（实时）──${RESET}"
SECS_LIMIT=25
START=$SECONDS
LAST_JOURNAL_TS=""
READY=0
while [ $((SECONDS - START)) -lt $SECS_LIMIT ]; do
  # 拿最近 30 行日志
  CURRENT="$(journalctl -u "$SERVICE_NAME" --no-pager -q -n 30 --since "30 seconds ago" 2>/dev/null \
              | sed 's/^/  /')"
  if [ "$CURRENT" != "$LAST_JOURNAL_TS" ]; then
    # 显示新增的行（简单 diff）
    if [ -z "$LAST_JOURNAL_TS" ]; then
      echo "$CURRENT"
    else
      diff <(echo "$LAST_JOURNAL_TS") <(echo "$CURRENT") | sed -n 's/^> //p'
    fi
    LAST_JOURNAL_TS="$CURRENT"
  fi
  # 检测启动成功标志
  if echo "$CURRENT" | grep -q "SOCKS5 listening"; then
    READY=1
    break
  fi
  # 检测明显失败
  if echo "$CURRENT" | grep -q "fatal:\|FATAL\|panicked at"; then
    break
  fi
  sleep 1
done
echo "${CYAN}── 日志结束 ──${RESET}"

# ── 报告 ────────────────────────────────────────────────────────────────────
echo
echo "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
ok "warp-rust ${VERSION} 已安装并运行"
echo "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
echo
echo "  SOCKS5      : ${BOLD}$BIND${RESET}"
if [ "$EXPOSE" = 1 ]; then
  echo "  鉴权        : ${BOLD}$USER_NAME${RESET} / ${BOLD}$PASS${RESET}"
else
  echo "  鉴权        : 无（仅本机 loopback 可达）"
fi
echo "  配置        : $CONF_FILE （权限 0640）"
echo "  数据        : $DATA_DIR"
echo "  metrics     : http://127.0.0.1:9090/metrics"
echo
echo "${BOLD}常用命令${RESET}"
echo "  ● 状态        : sudo systemctl status $SERVICE_NAME"
echo "  ● 实时日志    : sudo journalctl -u $SERVICE_NAME -f"
echo "  ● 最近日志    : sudo journalctl -u $SERVICE_NAME -n 100"
echo "  ● 重启        : sudo systemctl restart $SERVICE_NAME"
echo "  ● 停止        : sudo systemctl stop $SERVICE_NAME"
echo "  ● 日志占用    : sudo journalctl --disk-usage"
echo "  ● 清理旧日志  : sudo journalctl --vacuum-time=30d"
echo
echo "${BOLD}验证流量真的走 WARP${RESET}"
echo "  curl --socks5-hostname 127.0.0.1:$PORT https://1.1.1.1/cdn-cgi/trace"
echo "  期望看到 warp=on"
echo
echo "${BOLD}更新到最新版${RESET}"
echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh \\"
echo "    | sudo bash -s -- --update"
echo
echo "${BOLD}卸载${RESET}"
echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh \\"
echo "    | sudo bash -s -- --uninstall"
echo

# 服务真的起来了吗？
if [ "$READY" = 1 ] && systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "${BOLD}服务运行正常，SOCKS5 已监听 $BIND${RESET}"
elif systemctl is-active --quiet "$SERVICE_NAME"; then
  warn "服务 active 但 25 秒内没看到 'SOCKS5 listening'（WARP 握手慢？）"
  echo "  跟踪日志：${BOLD}sudo journalctl -u $SERVICE_NAME -f${RESET}"
else
  warn "服务未变 active；以下是最近日志："
  journalctl -u "$SERVICE_NAME" --no-pager -q -n 40 2>/dev/null | sed 's/^/  /'
  echo
  echo "完整排查：${BOLD}sudo journalctl -u $SERVICE_NAME -n 200${RESET}"
fi
