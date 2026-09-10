#!/usr/bin/env bash
#
# tune-concurrency.sh — 把 warp-rust 的并发限流从「个人代理」默认值调到高并发档
#
# 为什么需要它：`max_concurrent_connections` 默认 1024，而 install.sh 把这个值
# **写死**在生成的配置里；`--update` 只替换二进制、不改配置，所以升级到再新的
# 版本也不会自动提高并发。本脚本直接改配置并重启服务。
#
# 关键约束（改再多配置也绕不过）：
#   · netstack 的 TCP ephemeral 端口池固定 32768 个 —— 这是**单实例**并发 TCP
#     连接的架构天花板。需要更多就得多实例 + 负载均衡。
#   · 每条已建立连接实打实占用 2×tcp_buffer_size + 2×relay_buffer_size 物理内存
#     （smoltcp 的 buffer 是创建时预分配，不是按需增长）。所以并发上限由内存决定，
#     本脚本会据此自动计算，不会盲目写一个大数字把机器打爆。
#
# 用法：
#   sudo bash tune-concurrency.sh                    # 自动按内存计算（balanced 档）
#   sudo bash tune-concurrency.sh --profile max-conn # 榨并发：每连接内存再减半
#   sudo bash tune-concurrency.sh --max 16384        # 手动指定并发上限
#   sudo bash tune-concurrency.sh --dry-run          # 只看会改什么，不落盘
#   sudo bash tune-concurrency.sh --revert           # 回滚到最近一次备份
#
# 两个档位（并发与单连接吞吐是此消彼长的，smoltcp 的 buffer 固定预分配，
# 不能按需增长，所以必须在两者之间选）：
#   balanced（默认）  tcp=128KiB relay=32KiB → 每连接 320KiB，单连接 ~7Mbps@150ms
#   max-conn          tcp=64KiB  relay=16KiB → 每连接 160KiB，单连接 ~3.5Mbps@150ms
# 同样内存下 max-conn 的并发是 balanced 的两倍。测速看的是多线程总带宽，
# 通常 8-16 线程，所以单连接降一半对测速成绩影响远小于并发被拒。

set -euo pipefail

CONF_FILE="${WARP_RUST_CONF:-/etc/warp-rust/config.toml}"
SERVICE_NAME="warp-rust"
DRY_RUN=0
REVERT=0
FORCE_MAX=""
PROFILE="balanced"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
die()  { echo "${RED}✗ $*${RESET}" >&2; exit 1; }
info() { echo "${CYAN}▸${RESET} $*"; }
warn() { echo "${YELLOW}!${RESET} $*"; }
ok()   { echo "${GREEN}✓${RESET} $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --max)     FORCE_MAX="${2:?--max 需要一个数值}"; shift ;;
    --profile) PROFILE="${2:?--profile 需要 balanced 或 max-conn}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    --revert)  REVERT=1 ;;
    --conf)    CONF_FILE="${2:?--conf 需要路径}"; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) die "未知参数：$1（用 --help 看帮助）" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash $0）"
[ -f "$CONF_FILE" ] || die "找不到配置文件 $CONF_FILE（可用 --conf 指定）"

# ── 回滚 ────────────────────────────────────────────────────────────────────
if [ "$REVERT" -eq 1 ]; then
  latest="$(find "$(dirname "$CONF_FILE")" -maxdepth 1 -name "$(basename "$CONF_FILE").tune-bak.*" \
            -type f 2>/dev/null | sort | tail -1)"
  [ -n "$latest" ] || die "没有找到备份文件"
  cp -a "$latest" "$CONF_FILE"
  ok "已回滚到 $latest"
  systemctl restart "$SERVICE_NAME" && ok "服务已重启"
  exit 0
fi

# ── 读取现有值 ──────────────────────────────────────────────────────────────
# 在指定 [section] 内读一个 key 的值（去注释、去空白）。找不到输出空串。
read_toml() {
  local file="$1" section="$2" key="$3"
  awk -v sect="$section" -v key="$key" '
    $0 ~ "^[[:space:]]*\\[" sect "\\][[:space:]]*(#.*)?$" { inside=1; next }
    inside && /^[[:space:]]*\[/ { exit }
    inside {
      line=$0; sub(/#.*/, "", line)
      if (line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        sub(/^[^=]*=/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        gsub(/"/, "", line)
        print line; exit
      }
    }
  ' "$file"
}

# 在指定 [section] 内设置 key=value；key 不存在则在段末插入，段不存在则追加。
set_toml() {
  local file="$1" section="$2" key="$3" value="$4" tmp
  tmp="$(mktemp)"
  awk -v sect="$section" -v key="$key" -v val="$value" '
    BEGIN { inside=0; done=0; seen_section=0 }
    {
      if ($0 ~ "^[[:space:]]*\\[" sect "\\][[:space:]]*(#.*)?$") {
        inside=1; seen_section=1; print; next
      }
      # 离开目标段：若还没写入，先补一行再输出当前行
      if (inside && $0 ~ /^[[:space:]]*\[/) {
        if (!done) { print key " = " val; done=1 }
        inside=0; print; next
      }
      if (inside && !done) {
        line=$0; sub(/#.*/, "", line)
        if (line ~ "^[[:space:]]*" key "[[:space:]]*=") {
          print key " = " val; done=1; next
        }
      }
      print
    }
    END {
      if (inside && !done) { print key " = " val; done=1 }
      if (!seen_section) { print ""; print "[" sect "]"; print key " = " val }
      else if (!done)    { print key " = " val }
    }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
}

CUR_MAX="$(read_toml "$CONF_FILE" limits max_concurrent_connections)"
CUR_TCPBUF="$(read_toml "$CONF_FILE" warp tcp_buffer_size)"
CUR_RELAY="$(read_toml "$CONF_FILE" limits relay_buffer_size)"
CUR_DIALS="$(read_toml "$CONF_FILE" limits max_pending_dials)"
CUR_CTO="$(read_toml "$CONF_FILE" limits connect_timeout)"

# ── 目标值：每连接内存减半，并发按可用内存推算 ──────────────────────────────
case "$PROFILE" in
  balanced) NEW_TCPBUF=131072; NEW_RELAY=32768 ;;   # 128KiB / 32KiB
  max-conn) NEW_TCPBUF=65536;  NEW_RELAY=16384 ;;   # 64KiB / 16KiB —— 并发翻倍
  *) die "--profile 只支持 balanced 或 max-conn（收到：$PROFILE）" ;;
esac
NEW_DIALS=512       # 建连速率上限 = max_pending_dials / connect_timeout
NEW_CTO='"8s"'
PER_CONN=$(( (NEW_TCPBUF + NEW_RELAY) * 2 ))   # 每条连接字节数 = 320KiB

# 端口池硬上限：netstack EPHEMERAL_PORT_COUNT = 32768
PORT_CEILING=32768
# 配置层校验上限
CONFIG_CEILING=16384

MEM_KB="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
[ "$MEM_KB" -gt 0 ] 2>/dev/null || die "无法读取 /proc/meminfo，请用 --max 手动指定"
MEM_BYTES=$(( MEM_KB * 1024 ))

if [ -n "$FORCE_MAX" ]; then
  case "$FORCE_MAX" in
    ''|*[!0-9]*) die "--max 必须是正整数：$FORCE_MAX" ;;
  esac
  NEW_MAX="$FORCE_MAX"
else
  # 目标：满并发时连接缓冲不超过物理内存的 50%
  NEW_MAX=$(( MEM_BYTES / 2 / PER_CONN ))
  # 向下取整到 1024 的倍数，便于阅读
  NEW_MAX=$(( NEW_MAX / 1024 * 1024 ))
  [ "$NEW_MAX" -lt 1024 ] && NEW_MAX=1024
fi

[ "$NEW_MAX" -gt "$CONFIG_CEILING" ] && {
  warn "计算值 $NEW_MAX 超过配置层上限 $CONFIG_CEILING，已收敛"
  NEW_MAX=$CONFIG_CEILING
}

BUDGET=$(( NEW_MAX * PER_CONN ))
PCT=$(( BUDGET * 100 / MEM_BYTES ))

echo
echo "${BOLD}════════ warp-rust 并发调优 ════════${RESET}"
printf "  档位            : %s\n" "$PROFILE"
printf "  物理内存        : %.1f GiB\n" "$(awk -v b="$MEM_BYTES" 'BEGIN{print b/1073741824}')"
printf "  每连接占用      : %d KiB  (2×tcp_buffer + 2×relay_buffer)\n" "$(( PER_CONN / 1024 ))"
echo
printf "  %-28s %-12s → %s\n" "max_concurrent_connections" "${CUR_MAX:-<未设置>}" "$NEW_MAX"
printf "  %-28s %-12s → %s\n" "[warp] tcp_buffer_size"      "${CUR_TCPBUF:-<未设置>}" "$NEW_TCPBUF"
printf "  %-28s %-12s → %s\n" "relay_buffer_size"           "${CUR_RELAY:-<未设置>}" "$NEW_RELAY"
printf "  %-28s %-12s → %s\n" "max_pending_dials"           "${CUR_DIALS:-<未设置>}" "$NEW_DIALS"
printf "  %-28s %-12s → %s\n" "connect_timeout"             "${CUR_CTO:-<未设置>}" "8s"
echo
printf "  满并发内存预算  : %.1f GiB (物理内存的 %d%%)\n" \
       "$(awk -v b="$BUDGET" 'BEGIN{print b/1073741824}')" "$PCT"
echo "${BOLD}════════════════════════════════════${RESET}"
echo

if [ "$PCT" -ge 80 ]; then
  die "内存预算达 ${PCT}%，过高。请用 --max 指定更小的值，或换内存更大的机器"
fi
if [ "$PCT" -ge 60 ]; then
  warn "内存预算达 ${PCT}%，偏高；若机器上还跑着别的服务请用 --max 调小"
fi
if [ "$NEW_MAX" -ge "$PORT_CEILING" ]; then
  warn "并发已接近 netstack 端口池上限 ${PORT_CEILING}；再高必须拆多实例"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  info "--dry-run：未改动任何文件"
  exit 0
fi

BACKUP="${CONF_FILE}.tune-bak.$(date +%Y%m%d-%H%M%S)"
cp -a "$CONF_FILE" "$BACKUP"
ok "配置已备份到 $BACKUP"

set_toml "$CONF_FILE" limits max_concurrent_connections "$NEW_MAX"
set_toml "$CONF_FILE" limits max_pending_dials          "$NEW_DIALS"
set_toml "$CONF_FILE" limits relay_buffer_size          "$NEW_RELAY"
set_toml "$CONF_FILE" limits connect_timeout            "$NEW_CTO"
set_toml "$CONF_FILE" warp   tcp_buffer_size            "$NEW_TCPBUF"
ok "配置已更新"

if ! systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}.service"; then
  warn "未检测到 systemd 服务 ${SERVICE_NAME}；配置已改，请自行重启进程"
  exit 0
fi

info "重启服务..."
systemctl restart "$SERVICE_NAME"
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "服务已重启并在运行"
  echo
  info "验证生效（新值应出现在启动日志里）："
  echo "    journalctl -u ${SERVICE_NAME} -n 30 --no-pager | grep -i 'max_concurrent\\|SOCKS5 listening'"
  echo
  info "持续观察这三个指标："
  echo "    watch -n5 \"curl -s localhost:9090/metrics | grep -E 'conns_rejected|netstack_sockets_active|ephemeral_port_exhausted'\""
  echo
  echo "  · conns_rejected_total 仍在涨      → 并发上限还是不够，加 --max 再调"
  echo "  · ephemeral_port_exhausted 非零    → 撞到 32768 端口池上限，必须拆多实例"
  echo "  · netstack_sockets_active 稳定不涨 → 正常"
else
  warn "服务未能启动，正在回滚配置..."
  cp -a "$BACKUP" "$CONF_FILE"
  systemctl restart "$SERVICE_NAME" || true
  die "已回滚。请看 journalctl -u ${SERVICE_NAME} -n 50"
fi
