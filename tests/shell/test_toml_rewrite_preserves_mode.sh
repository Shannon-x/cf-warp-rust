#!/usr/bin/env bash
#
# 回归：改写 TOML 时必须保留原文件的权限与属主。
#
# v0.4.7 首个版本用 `mv "$tmp" "$file"` 落盘，把 mktemp 的 0600 root:root 带到了
# /etc/warp-rust/config.toml（原本 0640 root:warp-rust）。服务以非 root 的
# warp-rust 用户运行，权限一变立刻起不来：
#     fatal: figment: Permission denied (os error 13) in /etc/warp-rust/config.toml
# 内容测试全绿也发现不了——必须单独钉住文件模式。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# 跨平台读取文件权限（CI 是 Linux，开发机可能是 macOS）
file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

CONF="$TMPDIR_TEST/config.toml"
cat > "$CONF" <<'TOML'
[warp]
mtu = 1280
tcp_buffer_size = 262144

[limits]
max_concurrent_connections = 1024
relay_buffer_size = 65536
TOML
chmod 640 "$CONF"
BEFORE="$(file_mode "$CONF")"
[ "$BEFORE" = "640" ] || { echo "FAIL: fixture 权限应为 640，实际 $BEFORE" >&2; exit 1; }

fail=0

# ── 被测对象 1：scripts/tune-concurrency.sh 的 set_toml ────────────────────
(
  eval "$(awk '/^set_toml\(\) \{/,/^\}/' "$ROOT/scripts/tune-concurrency.sh")"
  set_toml "$CONF" limits max_concurrent_connections 12288
  set_toml "$CONF" warp   tcp_buffer_size            65536
)
AFTER="$(file_mode "$CONF")"
if [ "$AFTER" != "640" ]; then
  echo "FAIL: tune-concurrency.sh set_toml 把权限改成了 $AFTER（应保持 640）" >&2
  fail=1
fi
grep -q 'max_concurrent_connections = 12288' "$CONF" || { echo "FAIL: set_toml 未改写内容" >&2; fail=1; }
grep -q 'tcp_buffer_size = 65536' "$CONF" || { echo "FAIL: set_toml 未改写内容" >&2; fail=1; }

# ── 被测对象 2：install.sh 的 write_toml_key ───────────────────────────────
chmod 640 "$CONF"
(
  eval "$(awk '/^write_toml_key\(\) \{/,/^\}/' "$ROOT/install.sh")"
  write_toml_key "$CONF" limits relay_buffer_size 16384
)
AFTER2="$(file_mode "$CONF")"
if [ "$AFTER2" != "640" ]; then
  echo "FAIL: install.sh write_toml_key 把权限改成了 $AFTER2（应保持 640）" >&2
  fail=1
fi
grep -q 'relay_buffer_size = 16384' "$CONF" || { echo "FAIL: write_toml_key 未改写内容" >&2; fail=1; }

# ── 更严格：0600 与 0644 也要原样保留，不能被规范化成某个固定值 ────────────
for mode in 600 644; do
  chmod "$mode" "$CONF"
  (
    eval "$(awk '/^set_toml\(\) \{/,/^\}/' "$ROOT/scripts/tune-concurrency.sh")"
    set_toml "$CONF" limits max_concurrent_connections 2048
  )
  got="$(file_mode "$CONF")"
  if [ "$got" != "$mode" ]; then
    echo "FAIL: 原权限 $mode 被改成了 $got" >&2
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "OK: TOML 改写保留文件权限（640/600/644 均验证）"
else
  exit 1
fi
