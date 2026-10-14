#!/usr/bin/env bash
# Ayana 一键安装引导：自己拉包 → 预检 → 缺啥装啥 / 全齐则跳过。
#
# 用法（目标机上直接跑）：
#   curl -fsSL https://raw.githubusercontent.com/wwqjss/Ayana/main/deploy/bootstrap.sh -o bootstrap.sh
#   bash bootstrap.sh --system
#   bash bootstrap.sh --user
#   bash bootstrap.sh --system --check
#
# 版本：
#   默认 latest（跟随 GitHub 最新 Release，文档不用改版本号）
#   固定版本：AYANA_VERSION=v0.7.3 bash bootstrap.sh --system
#
# 校验（可选）：
#   AYANA_SHA256=<hash> bash bootstrap.sh ...
#   不设则拉取 Release 上的 <asset>.sha256；仍没有则跳过并警告
set -euo pipefail

AYANA_VERSION="${AYANA_VERSION:-latest}"
AYANA_REPO="${AYANA_REPO:-wwqjss/Ayana}"
AYANA_WORK_DIR="${AYANA_WORK_DIR:-$HOME/ayana-install-$$}"
API="https://api.github.com/repos/${AYANA_REPO}"
INSTALL_ARGS=("$@")
[[ ${#INSTALL_ARGS[@]} -gt 0 ]] || INSTALL_ARGS=(--user)

log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }
fetch() { # url -> stdout
  if have curl; then curl -fsSL --connect-timeout 20 "$1"
  elif have wget; then wget -qO- "$1"
  else die "need curl or wget"
  fi
}
download() { # url dest
  if have curl; then curl -fsSL --connect-timeout 20 "$1" -o "$2"
  elif have wget; then wget -qO "$2" "$1"
  else die "need curl or wget"
  fi
}

# 解析资产名：latest 或具体 tag
log "==> resolve release (${AYANA_VERSION})"
if [[ "$AYANA_VERSION" == "latest" ]]; then
  # 稳定文件名，永远指向最新
  ASSET="ayana-install.tar.gz"
  TAG_URL_PART="latest/download"
  META_URL="${API}/releases/latest"
else
  # 具体版本：优先版本化文件名，回退稳定名
  VER_NUM="${AYANA_VERSION#v}"
  ASSET="ayana-${VER_NUM}-install.tar.gz"
  TAG_URL_PART="download/${AYANA_VERSION}"
  META_URL="${API}/releases/tags/${AYANA_VERSION}"
fi

# 有 API 时校对资产是否存在（失败不致命，仍按约定 URL 下载）
if meta="$(fetch "$META_URL" 2>/dev/null)"; then
  log "    release ok"
else
  warn "release meta unavailable, use fixed URL"
fi

URL="https://github.com/${AYANA_REPO}/releases/${TAG_URL_PART}/${ASSET}"
mkdir -p "$AYANA_WORK_DIR"
TARBALL="$AYANA_WORK_DIR/$ASSET"

log "==> download $URL"
download "$URL" "$TARBALL" || die "download failed: $URL"

# 校验
if [[ -n "${AYANA_SHA256:-}" ]]; then
  expect="$AYANA_SHA256"
  log "==> verify sha256 (AYANA_SHA256)"
elif sum="$(fetch "${URL}.sha256" 2>/dev/null | awk '{print $1}')" && [[ -n "$sum" ]]; then
  expect="$sum"
  log "==> verify sha256 (from ${ASSET}.sha256)"
else
  expect=""
  warn "no sha256 provided and no ${ASSET}.sha256; skip verify"
fi

if [[ -n "$expect" ]]; then
  actual="$(sha256sum "$TARBALL" | awk '{print $1}')"
  [[ "$actual" == "$expect" ]] || die "sha256 mismatch: expect=$expect actual=$actual"
  log "    sha256 ok"
fi

log "==> extract"
tar -xzf "$TARBALL" -C "$AYANA_WORK_DIR"

ROOT=""
while IFS= read -r cand; do
  dir="$(dirname "$(dirname "$cand")")"
  if [[ -f "$dir/deploy/install.sh" ]]; then ROOT="$dir"; break; fi
done < <(find "$AYANA_WORK_DIR" -maxdepth 3 -type f -path '*/ayana/main.py')
[[ -n "$ROOT" ]] || die "package layout unexpected"

log "==> run install.sh ${INSTALL_ARGS[*]}"
bash "$ROOT/deploy/install.sh" "${INSTALL_ARGS[@]}"
