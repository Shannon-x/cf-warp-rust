#!/usr/bin/env bash
#
# run-docker.sh — 一键容器启动（非交互、参数化）
#
# 用法：
#   ./scripts/run-docker.sh                       # 默认 127.0.0.1:1080，无鉴权
#   ./scripts/run-docker.sh 1081                  # 改端口
#   ./scripts/run-docker.sh 1080 --expose         # 对外 0.0.0.0:1080，自动生成强密码
#   ./scripts/run-docker.sh 1080 --expose --user me --pass 'Xx****16'
#   ./scripts/run-docker.sh --stop                # 仅停止容器
#
# 镜像优先 pull GHCR；拉不到则本地 docker build。

set -euo pipefail

CONTAINER="warp-rust"
IMAGE="${WARP_RUST_IMAGE:-ghcr.io/shannon-x/cf-warp-rust:latest}"

if [ "${1:-}" = "--stop" ]; then
  docker rm -f "$CONTAINER" >/dev/null 2>&1 && echo "✓ 已停止 $CONTAINER" || echo "$CONTAINER 未运行"
  exit 0
fi

PORT="${1:-1080}"; shift || true
EXPOSE=0; USER="warp"; PASS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expose)    EXPOSE=1 ;;
    --user)      USER="$2"; shift ;;
    --pass)      PASS="$2"; shift ;;
    -h|--help)
      sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
  shift
done

[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
  || { echo "端口非法：$PORT" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || { echo "未安装 docker" >&2; exit 4; }

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
ok_pw()  { local p="$1"; [ "${#p}" -ge 16 ] && [[ "$p" =~ [A-Z] ]] && [[ "$p" =~ [a-z] ]] && [[ "$p" =~ [0-9] ]]; }

# 决定宿主机绑定 IP 与鉴权
if [ "$EXPOSE" -eq 1 ]; then
  HOST_IP="0.0.0.0"
  if [ -z "$PASS" ]; then
    PASS="$(gen_pw)"; echo "✓ 自动生成强密码：$PASS" >&2
    echo "  请立即妥善保存。" >&2
  fi
  ok_pw "$PASS" || { echo "密码强度不够（≥16 位，含大小写和数字）" >&2; exit 3; }
else
  HOST_IP="127.0.0.1"
fi

cd "$(dirname "$0")/.."
CFG="./config.docker.toml"
{
  echo "# 由 scripts/run-docker.sh 自动生成"
  echo "[server]"
  # 容器内一律监听 0.0.0.0，由宿主侧 -p 决定对外暴露范围
  echo 'bind = "0.0.0.0:'"$PORT"'"'
  if [ "$EXPOSE" -eq 1 ]; then
    echo
    echo "[server.auth]"
    echo 'username = "'"$USER"'"'
    echo 'password = "'"$PASS"'"'
  fi
  cat <<EOF

[logging]
level = "info,warp_rust=info"
format = "pretty"

[warp]
data_dir = "/app/data"
device_model = "warp-rust"
refresh_interval = "24h"
register_cooldown = "10m"
mtu = 1420
tcp_buffer_size = 262144

[health]
interval = "30s"
timeout = "8s"
targets = ["1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:53"]
min_successes = 2

[recovery]
reconnect_after = 1
rebuild_config_after = 3
reregister_after = 5
rotate_identity_after = 10
backoff_min = "500ms"
backoff_max = "30s"

[metrics]
enabled = true
bind = "0.0.0.0:9090"

[hot_reload]
enabled = false

[limits]
max_concurrent_connections = 1024
max_pending_dials = 128
handshake_timeout = "10s"
connect_timeout = "12s"
happy_eyeballs_delay = "200ms"
max_dial_candidates = 8
max_parallel_dials = 2
idle_timeout = "300s"
relay_buffer_size = 65536
auth_fail_sleep = "1s"
relay_close_grace = "500ms"

[dns]
mode = "system"
servers = ["1.1.1.1:53", "1.0.0.1:53"]
timeout = "3s"
cache_ttl = "60s"
negative_ttl = "5s"
max_cache_entries = 4096
EOF
} > "$CFG"
chmod 600 "$CFG"

# 拉镜像，拉不到就本地构建
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "▸ 拉取镜像 $IMAGE..." >&2
  if ! docker pull "$IMAGE" >/dev/null 2>&1; then
    echo "! 拉取失败，改用本地 docker build" >&2
    IMAGE="cf-warp-rust:local"
    docker build -t "$IMAGE" .
  fi
fi

mkdir -p ./data
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
# 本脚本对宿主 -p 完全可控（默认 127.0.0.1，--expose 才放公网且强制 auth），
# 因此可以代表用户对宿主网络栈安全负责 —— 注入 WARP_RUST_TRUSTED_HOST_NET=1
# 解锁 v0.3.2+ 的容器内 0.0.0.0 + 无 auth 放行。镜像默认**不**设此 ENV
# （v0.3.2 BREAKING 收紧）：裸 `docker run` 用户必须自己加 -e 或加 auth。
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "$HOST_IP:$PORT:$PORT" \
  -p "127.0.0.1:9090:9090" \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/$CFG:/app/config.toml:ro" \
  -e WARP_RUST_TRUSTED_HOST_NET=1 \
  "$IMAGE" >/dev/null

echo "✓ 容器已启动：$CONTAINER ($IMAGE)" >&2
echo "  SOCKS5：$HOST_IP:$PORT  → 容器内 0.0.0.0:$PORT"
[ "$EXPOSE" -eq 1 ] && echo "  鉴权：$USER / 密码见上方或 $CFG"
echo "  metrics：http://127.0.0.1:9090/metrics"
echo "  日志：docker logs -f $CONTAINER"
echo "  停止：./scripts/run-docker.sh --stop"
