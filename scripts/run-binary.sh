#!/usr/bin/env bash
#
# run-binary.sh — 一键二进制启动（非交互、参数化）
#
# 用法：
#   ./scripts/run-binary.sh                       # 默认 127.0.0.1:1080，无鉴权
#   ./scripts/run-binary.sh 1081                  # 改端口
#   ./scripts/run-binary.sh 1080 --expose         # 对外 0.0.0.0:1080，自动生成强密码
#   ./scripts/run-binary.sh 1080 --expose --user me --pass 'Xx****16'   # 自定义密码
#
# --expose 时必须给出（或自动生成）强密码；弱密码直接拒绝。

set -euo pipefail

PORT="${1:-1080}"; shift || true
EXPOSE=0; USER="warp"; PASS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expose)    EXPOSE=1 ;;
    --user)      USER="$2"; shift ;;
    --pass)      PASS="$2"; shift ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
  shift
done

[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
  || { echo "端口非法：$PORT" >&2; exit 2; }

# pipefail-safe：先把随机字节全部读入 shell 变量，再过滤，再用 bash substring
# 截取，全程无下游管道 → 不可能触发 SIGPIPE。
gen_pw() {
  local raw chars
  if command -v openssl >/dev/null 2>&1; then
    raw=$(openssl rand -base64 36) || return 1
  else
    raw=$(head -c 512 /dev/urandom) || return 1
  fi
  chars=$(printf '%s' "$raw" | LC_ALL=C tr -dc 'A-Za-z0-9')
  printf '%s\n' "${chars:0:24}"
}
ok_pw() {
  local p="$1"
  [ "${#p}" -ge 16 ] && [[ "$p" =~ [A-Z] ]] && [[ "$p" =~ [a-z] ]] && [[ "$p" =~ [0-9] ]]
}

if [ "$EXPOSE" -eq 1 ]; then
  BIND="0.0.0.0:$PORT"
  if [ -z "$PASS" ]; then
    PASS="$(gen_pw)"
    echo "✓ 自动生成强密码：$PASS" >&2
    echo "  请立即妥善保存。" >&2
  fi
  ok_pw "$PASS" || { echo "密码强度不够（≥16 位，含大小写和数字）" >&2; exit 3; }
else
  BIND="127.0.0.1:$PORT"
fi

cd "$(dirname "$0")/.."
CFG="./config.runbin.toml"
{
  echo "# 由 scripts/run-binary.sh 自动生成"
  echo "[server]"
  echo "bind = \"$BIND\""
  if [ "$EXPOSE" -eq 1 ]; then
    echo
    echo "[server.auth]"
    printf 'username = "%s"\n' "$USER"
    printf 'password = "%s"\n' "$PASS"
  fi
  cat <<EOF

[logging]
level = "info,warp_rust=info"
format = "pretty"

[warp]
data_dir = "./data"
device_model = "warp-rust"
refresh_interval = "24h"
register_cooldown = "10m"
mtu = 1420
tcp_buffer_size = 1048576

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

[limits]
max_concurrent_connections = 1024
handshake_timeout = "10s"
idle_timeout = "300s"
relay_buffer_size = 262144
auth_fail_sleep = "1s"
EOF
} > "$CFG"
chmod 600 "$CFG"

if [ ! -x ./target/release/warp-rust ]; then
  if command -v cargo >/dev/null 2>&1; then
    echo "▸ 编译 release 二进制（首次较慢）..." >&2
    cargo build --release --quiet
  else
    # 没装 cargo —— 自动从 GitHub Release 下载预编译二进制
    REPO="${REPO:-Shannon-x/cf-warp-rust}"
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
      x86_64|amd64)  ARCH="x86_64" ;;
      aarch64|arm64) ARCH="aarch64" ;;
      *) echo "未装 cargo，且不支持的架构 $(uname -m)" >&2; exit 4 ;;
    esac
    case "$OS" in
      linux)
        TARGET="${ARCH}-unknown-linux-musl"
        EXT="tar.gz"
        BIN="warp-rust"
        ;;
      darwin)
        TARGET="${ARCH}-apple-darwin"
        EXT="tar.gz"
        BIN="warp-rust"
        ;;
      *) echo "未装 cargo，且不支持的系统 $OS（请用 install.sh 或手动下载 release）" >&2; exit 4 ;;
    esac

    command -v curl >/dev/null 2>&1 || { echo "缺 curl，无法下载 release 二进制" >&2; exit 4; }

    VERSION="${VERSION:-}"
    if [ -z "$VERSION" ]; then
      echo "▸ 查询 GitHub Release 最新版..." >&2
      VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
                  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
      [ -n "$VERSION" ] || { echo "无法查到最新版本号" >&2; exit 4; }
    fi
    NAME="warp-rust-${VERSION}-${TARGET}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${NAME}.${EXT}"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    echo "▸ 下载 ${URL}" >&2
    curl -fSL --progress-bar "$URL" -o "$TMP/$NAME.$EXT" \
      || { echo "下载失败" >&2; exit 4; }
    tar xzf "$TMP/$NAME.$EXT" -C "$TMP"
    mkdir -p ./target/release
    install -m 0755 "$TMP/$NAME/$BIN" "./target/release/warp-rust"
    echo "▸ 已安装预编译二进制到 ./target/release/warp-rust" >&2
  fi
fi

echo "▸ SOCKS5 监听：$BIND" >&2
[ "$EXPOSE" -eq 1 ] && echo "▸ 鉴权：$USER / 密码见上方或 $CFG" >&2
echo "▸ metrics：http://127.0.0.1:9090/metrics" >&2
echo "▸ Ctrl-C 退出" >&2

exec ./target/release/warp-rust --config "$CFG"
