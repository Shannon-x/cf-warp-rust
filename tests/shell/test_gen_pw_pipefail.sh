#!/usr/bin/env bash
# tests/shell/test_gen_pw_pipefail.sh
# 回归测试：bug7 — gen_pw 必须在 pipefail 下稳定返回 24 字符且 exit code = 0。
# 用法：bash tests/shell/test_gen_pw_pipefail.sh
set -euo pipefail

# 从 4 个脚本里挑一个 source 出 gen_pw（它们应是同一份实现）
SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# 把 install.sh 的 gen_pw 用 awk 抠出来跑（避免 source 整个 installer 触发副作用）
GEN_PW_SRC=$(awk '/^gen_pw\(\) \{/,/^\}/' "$SCRIPT_DIR/install.sh")
[ -n "$GEN_PW_SRC" ] || { echo "FAIL: 未在 install.sh 中找到 gen_pw" >&2; exit 1; }

eval "$GEN_PW_SRC"

fail=0
for i in $(seq 1 200); do
  set +e
  pw=$(gen_pw)
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "FAIL #$i: rc=$rc" >&2
    fail=1; break
  fi
  if [ "${#pw}" -ne 24 ]; then
    echo "FAIL #$i: len=${#pw} pw=$pw" >&2
    fail=1; break
  fi
  case "$pw" in
    *[!A-Za-z0-9]*) echo "FAIL #$i: 含非字母数字字符: $pw" >&2; fail=1; break ;;
  esac
done

if [ "$fail" -eq 0 ]; then
  echo "OK: gen_pw 200/200 通过 (pipefail-safe, len=24, alphanumeric)"
else
  exit 1
fi

# 进一步：3 个用 gen_pw 的脚本函数体必须完全一致（除注释外）
normalize() { awk "/^$1\\(\\) \\{/,/^\\}/" "$2" | grep -v '^[[:space:]]*#' | tr -s '[:space:]'; }
A=$(normalize gen_pw "$SCRIPT_DIR/install.sh")
B=$(normalize gen_pw "$SCRIPT_DIR/scripts/run-docker.sh")
C=$(normalize gen_pw "$SCRIPT_DIR/scripts/run-binary.sh")
[ "$A" = "$B" ] || { echo "FAIL: install.sh vs run-docker.sh 的 gen_pw 不一致" >&2; exit 1; }
[ "$A" = "$C" ] || { echo "FAIL: install.sh vs run-binary.sh 的 gen_pw 不一致" >&2; exit 1; }
echo "OK: 3 个用 gen_pw 的脚本函数体（去注释/去空白后）完全一致"

# quickstart.sh 用的是 generate_password 名字（语义同 gen_pw）；单独跑 200 轮
# pipefail 测试，并验证它的 raw=$(...) || return 1 + bash substring 三步实现
# 与 gen_pw 同构（一致性靠语义而非文本字串比较）。
GEN_PASSWORD_SRC=$(awk '/^generate_password\(\) \{/,/^\}/' "$SCRIPT_DIR/scripts/quickstart.sh")
[ -n "$GEN_PASSWORD_SRC" ] || { echo "FAIL: 未在 quickstart.sh 中找到 generate_password" >&2; exit 1; }
# 防回滚：本函数必须不再含 `| head -c`（pipefail-unsafe 的 head 提前关 pipe 写法）
if printf '%s' "$GEN_PASSWORD_SRC" | grep -q "| head -c"; then
    echo "FAIL: quickstart.sh generate_password 仍含 '| head -c'，pipefail 不安全" >&2
    exit 1
fi
# 必须有 raw=$(...) || return 1 这条 fail-fast 习语（与 gen_pw 一致）
if ! printf '%s' "$GEN_PASSWORD_SRC" | grep -q "raw=\$(.*) || return 1"; then
    echo "FAIL: quickstart.sh generate_password 缺少 raw=\$(...) || return 1 fail-fast" >&2
    exit 1
fi
eval "$GEN_PASSWORD_SRC"
for i in $(seq 1 200); do
  set +e
  pw=$(generate_password)
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then echo "FAIL quickstart #$i: rc=$rc" >&2; exit 1; fi
  if [ "${#pw}" -ne 24 ]; then echo "FAIL quickstart #$i: len=${#pw}" >&2; exit 1; fi
  case "$pw" in *[!A-Za-z0-9]*) echo "FAIL quickstart #$i: $pw" >&2; exit 1 ;; esac
done
echo "OK: quickstart.sh generate_password 200/200 通过 (pipefail-safe, len=24, alphanumeric)"
