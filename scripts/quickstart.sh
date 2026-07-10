#!/usr/bin/env bash
#
# quickstart.sh — warp-rust 一键交互式启动
#
# 引导你选择「二进制」或「容器」运行模式、SOCKS 端口、本地 / 对外暴露，
# 然后生成配置并启动。对外暴露时会强制设置用户名/密码（弱密码会被拒绝）。
#
# 用法：
#   ./scripts/quickstart.sh                 # 全交互
#   PORT=1080 ./scripts/quickstart.sh       # 预填端口，仍交互问其它项

set -euo pipefail

# ── 通用工具 ─────────────────────────────────────────────────────────────────
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

die()     { echo "${RED}错误：$*${RESET}" >&2; exit 1; }
info()    { echo "${CYAN}▸${RESET} $*"; }
warn()    { echo "${YELLOW}!${RESET} $*"; }
success() { echo "${GREEN}✓${RESET} $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少依赖：$1"
}

ask() {
  # ask "prompt" "default" -> echoes the answer
  local prompt="$1" default="${2:-}" reply
  if [ -n "$default" ]; then
    read -r -p "$prompt [$default] " reply
    echo "${reply:-$default}"
  else
    read -r -p "$prompt " reply
    echo "$reply"
  fi
}

ask_secret() {
  # 不回显的密码输入
  local prompt="$1" reply
  read -r -s -p "$prompt " reply
  echo >&2
  echo "$reply"
}

valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
}

generate_password() {
  # 24 位字母数字混合，约 143 bits 熵；只用 alphanumeric 是为了避免在 TOML
  # 和命令行里因转义产生奇怪 bug。
  # pipefail-safe：先把随机字节全部读入 shell 变量，再过滤，再用 bash
  # substring 截取，全程不存在「下游 head 提前关 pipe → 上游 SIGPIPE」的风险。
  local raw chars
  if command -v openssl >/dev/null 2>&1; then
    raw=$(openssl rand -base64 36) || return 1
  else
    raw=$(head -c 512 /dev/urandom) || return 1
  fi
  chars=$(printf '%s' "$raw" | LC_ALL=C tr -dc 'A-Za-z0-9')
  printf '%s\n' "${chars:0:24}"
}

validate_password() {
  local pw="$1"
  [ "${#pw}" -ge 16 ]   || { warn "密码至少 16 位"; return 1; }
  [[ "$pw" =~ [A-Z] ]]  || { warn "密码需包含至少一个大写字母"; return 1; }
  [[ "$pw" =~ [a-z] ]]  || { warn "密码需包含至少一个小写字母"; return 1; }
  [[ "$pw" =~ [0-9] ]]  || { warn "密码需包含至少一个数字"; return 1; }
  return 0
}

write_config() {
  # args: path, bind, [username, password]
  local path="$1" bind="$2" user="${3:-}" pass="${4:-}"
  mkdir -p "$(dirname "$path")"
  {
    echo "# 由 quickstart.sh 自动生成；再次运行脚本会覆盖此文件"
    echo
    echo "[server]"
    echo "bind = \"$bind\""
    if [ -n "$user" ]; then
      echo
      echo "[server.auth]"
      echo "username = \"$user\""
      echo "password = \"$pass\""
    fi
    cat <<'EOF'

[logging]
level = "info,warp_rust=info"
format = "pretty"

[warp]
data_dir = "./data"
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
bind = "127.0.0.1:9090"

[hot_reload]
enabled = true

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
  } > "$path"
  chmod 600 "$path"
}

# ── 主流程 ───────────────────────────────────────────────────────────────────
banner() {
  cat <<EOF
${BOLD}════════════════════════════════════════════════════════${RESET}
${BOLD}  warp-rust 一键启动${RESET}
  通过 Cloudflare WARP 出口的 SOCKS5 + UDP 代理
${BOLD}════════════════════════════════════════════════════════${RESET}

注意事项：
  • 默认绑定 127.0.0.1，仅本机可用（最安全）
  • 选择对外暴露时会强制要求强密码鉴权
  • 程序使用用户态 WireGuard，${BOLD}不会${RESET}修改宿主路由表/iptables/TUN
  • 卸载方式：停止进程或容器即可，无任何残留

EOF
}

main() {
  banner
  cd "$(dirname "$0")/.."

  # 1) 模式
  local mode
  while :; do
    mode=$(ask "运行模式？[1=二进制 cargo build, 2=Docker 容器]" "1")
    case "$mode" in
      1|binary) mode=binary; break ;;
      2|docker) mode=docker; break ;;
      *) warn "请输入 1 或 2";;
    esac
  done

  # 2) 端口
  local port="${PORT:-}"
  while ! valid_port "$port"; do
    port=$(ask "SOCKS5 监听端口" "1080")
    valid_port "$port" || warn "端口必须是 1-65535 的整数"
  done

  # 3) 绑定范围 + 鉴权
  local bind_choice bind user="" pass=""
  bind_choice=$(ask "绑定范围？[L=仅本机 127.0.0.1（推荐）, E=对外 0.0.0.0]" "L")
  case "${bind_choice,,}" in
    e|external|0.0.0.0)
      bind="0.0.0.0:$port"
      warn "对外暴露会让任何能到达本机 $port 端口的人都能用这个代理。"
      warn "本脚本将${BOLD}强制启用${RESET}用户名+密码鉴权。"
      user=$(ask "代理用户名" "warp")
      while :; do
        pass=$(ask_secret "代理密码（留空则自动生成 24 位强密码）：")
        if [ -z "$pass" ]; then
          pass=$(generate_password)
          success "已生成强密码：${BOLD}$pass${RESET}"
          warn "请立刻把它保存到密码管理器；脚本不会再次显示。"
          break
        fi
        if validate_password "$pass"; then
          break
        fi
      done
      ;;
    *)
      bind="127.0.0.1:$port"
      ;;
  esac

  # 4) 写配置
  local cfg="./config.toml"
  if [ -f "$cfg" ]; then
    local overwrite
    overwrite=$(ask "$cfg 已存在，覆盖？[y/N]" "N")
    case "${overwrite,,}" in y|yes) ;; *) cfg="./config.quickstart.toml"; warn "改写入 $cfg" ;; esac
  fi
  write_config "$cfg" "$bind" "$user" "$pass"
  success "已生成配置：$cfg（权限 0600）"

  # 5) 启动
  case "$mode" in
    binary)
      require_cmd cargo
      info "编译 release 二进制（首次较慢）..."
      cargo build --release --quiet
      success "构建完成。启动中（前台运行；Ctrl-C 退出）..."
      echo
      echo "  SOCKS5：$bind"
      [ -n "$user" ] && echo "  鉴权：用户名 $user / 密码已写入 $cfg"
      echo "  metrics：http://127.0.0.1:9090/metrics"
      echo "  数据目录：./data/"
      echo
      exec ./target/release/warp-rust --config "$cfg"
      ;;
    docker)
      require_cmd docker
      local image="ghcr.io/shannon-x/cf-warp-rust:latest"
      info "尝试拉取镜像 $image..."
      if ! docker pull "$image" >/dev/null 2>&1; then
        warn "未能拉取（也许还没发布），改为本地构建..."
        docker build -t cf-warp-rust:local .
        image="cf-warp-rust:local"
      fi
      mkdir -p ./data
      local host_ip="${bind%:*}" container_port="$port"
      local publish="$host_ip:$container_port:$container_port"
      success "启动容器（detached）..."
      docker rm -f warp-rust >/dev/null 2>&1 || true
      docker run -d \
        --name warp-rust \
        --restart unless-stopped \
        -p "$publish" \
        -p "127.0.0.1:9090:9090" \
        -v "$(pwd)/data:/app/data" \
        -v "$(pwd)/$cfg:/app/config.toml:ro" \
        -e WARP_RUST_SERVER__BIND="0.0.0.0:$container_port" \
        -e WARP_RUST_TRUSTED_HOST_NET=1 \
        "$image"
      echo
      echo "  SOCKS5：$bind  → 容器内 0.0.0.0:$container_port"
      [ -n "$user" ] && echo "  鉴权：用户名 $user / 密码已写入 $cfg"
      echo "  metrics：http://127.0.0.1:9090/metrics"
      echo "  日志：docker logs -f warp-rust"
      echo "  停止：docker stop warp-rust"
      ;;
  esac
}

main "$@"
