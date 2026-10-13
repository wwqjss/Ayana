#!/usr/bin/env bash
# Ayana 通用安装引导：从 GitHub 拉安装包，再跑预检幂等安装脚本。
# - 有就跳过，缺了才装
# - 不覆盖已有 secrets.json / config.json
#
# 用法：
#   bash bootstrap.sh --user
#   sudo bash bootstrap.sh --system
#   sudo bash bootstrap.sh --system --check   # 只检查
set -euo pipefail

AYANA_VERSION="${AYANA_VERSION:-v0.7.2}"
AYANA_REPO="${AYANA_REPO:-wwqjss/Ayana}"
ASSET_NAME="${AYANA_ASSET:-ayana-${AYANA_VERSION#v}-install.tar.gz}"
WORK_DIR="${AYANA_WORK_DIR:-$(pwd)/ayana-install-$$}"
RELEASE_URL="${AYANA_RELEASE_URL:-https://github.com/${AYANA_REPO}/releases/download/${AYANA_VERSION}/${ASSET_NAME}}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# 透传参数给 install.sh（--user/--system/--check/--force/--prefix 等）
INSTALL_ARGS=("$@")
if [[ ${#INSTALL_ARGS[@]} -eq 0 ]]; then
  INSTALL_ARGS=(--user)
fi

log "==> fetch Ayana ${AYANA_VERSION} from GitHub"
mkdir -p "$WORK_DIR"
TARBALL="$WORK_DIR/$ASSET_NAME"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$RELEASE_URL" -o "$TARBALL" || die "download failed: $RELEASE_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TARBALL" "$RELEASE_URL" || die "download failed: $RELEASE_URL"
else
  die "need curl or wget"
fi

log "==> extract"
tar -xzf "$TARBALL" -C "$WORK_DIR"

# 包根：包含 ayana/main.py 与 deploy/install.sh 的目录
ROOT=""
while IFS= read -r candidate; do
  dir="$(dirname "$candidate")"
  dir="$(dirname "$dir")"
  if [[ -f "$dir/deploy/install.sh" ]]; then
    ROOT="$dir"
    break
  fi
done < <(find "$WORK_DIR" -maxdepth 3 -type f -path '*/ayana/main.py')

[[ -n "$ROOT" ]] || die "package layout unexpected under $WORK_DIR"
[[ -f "$ROOT/deploy/install.sh" ]] || die "missing deploy/install.sh"

log "==> run universal installer"
log "    root=$ROOT"
bash "$ROOT/deploy/install.sh" "${INSTALL_ARGS[@]}"
