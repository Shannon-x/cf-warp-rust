#!/usr/bin/env bash
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
PORT=1080
EXPOSE=0
USER_NAME="warp"
PASS=""
VERSION=""
ACTION="install"

while [ $# -gt 0 ]; do
  case "$1" in
    --port)       PORT="${2:?}"; shift ;;
    --expose)     EXPOSE=1 ;;
    --user)       USER_NAME="${2:?}"; shift ;;
    --pass)       PASS="${2:?}"; shift ;;
    --version)    VERSION="${2:?}"; shift ;;
    --uninstall)  ACTION="uninstall" ;;
    --update)     ACTION="update" ;;
    --status)     ACTION="status" ;;
    -h|--help)    sed -n '2,33p' "$0" 2>/dev/null || sed -n '2,33p' /dev/stdin; exit 0 ;;
    *) die "未知参数：$1（用 --help 看帮助）" ;;
  esac
  shift
done

[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
  || die "端口非法：$PORT"

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
verify_sha256() {
  if command -v sha256sum >/dev/null; then sha256sum -c "$1"
  else
    # shasum -a 256 -c 也认 sha256sum 格式
    shasum -a 256 -c "$1"
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
  info "查询最新 release..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
              | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || die "无法获取最新版本号（GitHub API 速率限制？可用 --version 手动指定）"
fi

# ── 下载 + 校验 ─────────────────────────────────────────────────────────────
ASSET="warp-rust-${VERSION}-${TARGET}.tar.gz"
URL_TGZ="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
URL_SHA="${URL_TGZ}.sha256"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "下载 ${ASSET}（${VERSION}, ${TARGET}）"
curl -fSL --progress-bar "$URL_TGZ" -o "$TMP/$ASSET" \
  || die "下载失败：$URL_TGZ"
curl -fsSL "$URL_SHA" -o "$TMP/$ASSET.sha256" \
  || die "下载 sha256 失败"

info "校验 sha256..."
(cd "$TMP" && verify_sha256 "$ASSET.sha256" >/dev/null) \
  || die "sha256 校验失败 —— 文件可能损坏或被篡改"

info "解压..."
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
info "确保系统用户 $SERVICE_USER 存在..."
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  # 优先 useradd（util-linux），无则用 adduser（busybox/debian）
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
    || adduser --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

info "安装二进制 -> $INSTALL_BIN"
install -m 0755 -o root -g root "$EXTRACTED/warp-rust" "$INSTALL_BIN"

info "创建目录..."
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
info "生成配置 $CONF_FILE"
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
level = "info,warp_rust=info"
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
info "写 systemd unit -> $SERVICE_FILE"
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
info "启动服务..."
systemctl enable --now "$SERVICE_NAME" >/dev/null
sleep 2

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
echo "  ● 状态  : sudo systemctl status $SERVICE_NAME"
echo "  ● 日志  : sudo journalctl -u $SERVICE_NAME -f"
echo "  ● 重启  : sudo systemctl restart $SERVICE_NAME"
echo "  ● 停止  : sudo systemctl stop $SERVICE_NAME"
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
if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "服务运行正常（systemctl is-active = active）"
else
  warn "服务启动后未变 active，请用 journalctl -u $SERVICE_NAME -n 80 排查"
fi
