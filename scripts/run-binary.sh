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

# pipefail-safe：先一次性读固定字节再过滤再截取，避免 tr 收 SIGPIPE
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
} > "$CFG"
chmod 600 "$CFG"

if [ ! -x ./target/release/warp-rust ]; then
  command -v cargo >/dev/null 2>&1 || { echo "未安装 cargo，请先装 Rust" >&2; exit 4; }
  echo "▸ 编译 release 二进制（首次较慢）..." >&2
  cargo build --release --quiet
fi

echo "▸ SOCKS5 监听：$BIND" >&2
[ "$EXPOSE" -eq 1 ] && echo "▸ 鉴权：$USER / 密码见上方或 $CFG" >&2
echo "▸ metrics：http://127.0.0.1:9090/metrics" >&2
echo "▸ Ctrl-C 退出" >&2

exec ./target/release/warp-rust --config "$CFG"
