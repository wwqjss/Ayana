#!/usr/bin/env bash
# Ayana 一键安装（Linux）
# - 先检查环境；检查通过则不装，缺了才装对应项
# - 代码目录只读 / 数据目录可写（DB、secrets、日志、bootstrap 口令）
# - secrets.json 自动生成，不覆盖已有文件
# - 可选安装 systemd 单元（--system）
#
# 用法：
#   bash deploy/install.sh --user                 # 当前用户（默认）
#   sudo bash deploy/install.sh --system          # 系统级 + systemd
#   bash deploy/install.sh --check                # 只做环境/已装检查，不改任何东西
#   sudo bash deploy/install.sh --system --force  # 已装也强制重装代码/单元
#   sudo bash deploy/install.sh --system --prefix /opt/ayana --data /var/lib/ayana
set -euo pipefail

MODE="user"
PREFIX=""
DATA_DIR=""
CONF_DIR=""
HTTP_PORT="6200"
HTTP_HOST="127.0.0.1"
SKIP_PIP=0
CHECK_ONLY=0
FORCE=0
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \?//'
  exit "${1:-0}"
}

log() { printf '%s\n' "$*"; }
ok()  { printf '  [OK]   %s\n' "$*"; }
miss(){ printf '  [MISS] %s\n' "$*"; }
warn(){ printf '  [WARN] %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) MODE="user"; shift ;;
    --system) MODE="system"; shift ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --data) DATA_DIR="${2:?}"; shift 2 ;;
    --conf-dir) CONF_DIR="${2:?}"; shift 2 ;;
    --http-port) HTTP_PORT="${2:?}"; shift 2 ;;
    --http-host) HTTP_HOST="${2:?}"; shift 2 ;;
    --skip-pip) SKIP_PIP=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

# 脚本所在包/源码根目录
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$ROOT/ayana/main.py" ]] || die "run from extracted package (missing ayana/main.py)"
[[ -f "$ROOT/requirements.txt" ]] || die "missing requirements.txt"

if [[ "$MODE" == "system" ]]; then
  PREFIX="${PREFIX:-/opt/ayana}"
  DATA_DIR="${DATA_DIR:-/var/lib/ayana}"
  CONF_DIR="${CONF_DIR:-/etc/ayana}"
else
  PREFIX="${PREFIX:-$HOME/.local/share/ayana}"
  DATA_DIR="${DATA_DIR:-$HOME/.local/share/ayana-data}"
  CONF_DIR="${CONF_DIR:-$HOME/.config/ayana}"
fi

VENV="$PREFIX/.venv"
SECRETS="$CONF_DIR/secrets.json"
CONFIG="$CONF_DIR/config.json"
DB_PATH="$DATA_DIR/ayana.db"
LOG_PATH="$DATA_DIR/log/ayana.log"
UNIT_FILE="/etc/systemd/system/ayana.service"

# ---------------------------------------------------------------------------
# 1) 环境预检（缺了才会装；齐全则后面的安装步骤直接跳过）
# ---------------------------------------------------------------------------
log "==> 环境检查 (mode=$MODE)"
ENV_OK=1

if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PY_VER="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  PY_MAJOR="${PY_VER%%.*}"
  PY_MINOR="${PY_VER#*.}"
  if [[ "$PY_MAJOR" -gt 3 || ( "$PY_MAJOR" -eq 3 && "$PY_MINOR" -ge 11 ) ]]; then
    ok "python $PY_VER ($PYTHON_BIN)"
  else
    miss "python >= 3.11 required, found $PY_VER"
    ENV_OK=0
  fi
else
  miss "python3 not found (set PYTHON_BIN=...)"
  ENV_OK=0
fi

if command -v systemctl >/dev/null 2>&1; then
  ok "systemd available"
else
  if [[ "$MODE" == "system" ]]; then
    miss "systemctl not found (--system 需要 systemd)"
    ENV_OK=0
  else
    warn "systemctl not found (user 模式不需要)"
  fi
fi

if [[ "$MODE" == "system" && "$(id -u)" -ne 0 ]]; then
  miss "--system requires root"
  ENV_OK=0
elif [[ "$MODE" == "system" ]]; then
  ok "running as root"
fi

# 磁盘：安装目标所在文件系统剩余空间（KB），建议 >= 200MB
PARENT="$(dirname "$PREFIX")"
if DF_KB="$(df -Pk "$PARENT" 2>/dev/null | awk 'NR==2{print $4}')"; then
  if [[ "${DF_KB:-0}" -ge 204800 ]]; then
    ok "disk free ${DF_KB}KB on $PARENT"
  else
    warn "disk free ${DF_KB:-?}KB on $PARENT (<200MB, 可能不够装依赖)"
  fi
fi

# 代码树在安装前必须完整
for f in ayana/main.py ayana/config.py scripts/gen-secrets.py requirements.txt; do
  if [[ -f "$ROOT/$f" ]]; then
    ok "package file $f"
  else
    miss "package missing $f"
    ENV_OK=0
  fi
done

# ---------------------------------------------------------------------------
# 2) 已装状态探测（只读）
# ---------------------------------------------------------------------------
log "==> 已装检查"
HAS_CODE=0
HAS_VENV=0
HAS_SECRETS=0
HAS_CONFIG=0
HAS_DEPS=0
HAS_UNIT=0
HAS_ACTIVE=0

[[ -f "$PREFIX/ayana/main.py" ]] && HAS_CODE=1
[[ -x "$VENV/bin/python" ]] && HAS_VENV=1
[[ -f "$SECRETS" ]] && HAS_SECRETS=1
[[ -f "$CONFIG" ]] && HAS_CONFIG=1
[[ -f "$UNIT_FILE" ]] && HAS_UNIT=1

if [[ "$HAS_VENV" -eq 1 ]]; then
  if "$VENV/bin/python" -c 'import aiohttp' >/dev/null 2>&1; then
    HAS_DEPS=1
  fi
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ayana.service 2>/dev/null; then
  HAS_ACTIVE=1
fi

state_line() {
  local label="$1" val="$2"
  if [[ "$val" -eq 1 ]]; then ok "$label"; else miss "$label"; fi
}
state_line "code   $PREFIX" "$HAS_CODE"
state_line "venv   $VENV" "$HAS_VENV"
state_line "deps   aiohttp" "$HAS_DEPS"
state_line "secrets $SECRETS" "$HAS_SECRETS"
state_line "config  $CONFIG" "$HAS_CONFIG"
if [[ "$MODE" == "system" ]]; then
  state_line "unit    $UNIT_FILE" "$HAS_UNIT"
  state_line "service active" "$HAS_ACTIVE"
fi

# ---------------------------------------------------------------------------
# 3) 检查模式：只报告
# ---------------------------------------------------------------------------
if [[ "$CHECK_ONLY" -eq 1 ]]; then
  log ""
  if [[ "$ENV_OK" -eq 1 ]]; then
    log "环境检查通过。"
  else
    log "环境检查未通过，需要先补齐上面 [MISS] 项。"
    exit 1
  fi
  if [[ "$MODE" == "system" ]]; then
    if [[ "$HAS_CODE" -eq 1 && "$HAS_VENV" -eq 1 && "$HAS_DEPS" -eq 1 && "$HAS_SECRETS" -eq 1 && "$HAS_CONFIG" -eq 1 && "$HAS_UNIT" -eq 1 ]]; then
      log "已安装完整，无需再装。服务 active=$HAS_ACTIVE"
      exit 0
    fi
  else
    if [[ "$HAS_CODE" -eq 1 && "$HAS_VENV" -eq 1 && "$HAS_DEPS" -eq 1 && "$HAS_SECRETS" -eq 1 && "$HAS_CONFIG" -eq 1 ]]; then
      log "已安装完整，无需再装。"
      exit 0
    fi
  fi
  log "有缺失项，执行安装命令会补齐它们。"
  exit 2
fi

# ---------------------------------------------------------------------------
# 4) 全齐则跳过安装
# ---------------------------------------------------------------------------
complete=0
if [[ "$MODE" == "system" ]]; then
  [[ "$HAS_CODE" -eq 1 && "$HAS_VENV" -eq 1 && "$HAS_DEPS" -eq 1 \
     && "$HAS_SECRETS" -eq 1 && "$HAS_CONFIG" -eq 1 && "$HAS_UNIT" -eq 1 ]] && complete=1
else
  [[ "$HAS_CODE" -eq 1 && "$HAS_VENV" -eq 1 && "$HAS_DEPS" -eq 1 \
     && "$HAS_SECRETS" -eq 1 && "$HAS_CONFIG" -eq 1 ]] && complete=1
fi

if [[ "$complete" -eq 1 && "$FORCE" -eq 0 ]]; then
  log ""
  log "==> 检查通过，已安装完整，跳过安装。"
  if [[ "$MODE" == "system" && "$HAS_ACTIVE" -eq 0 ]]; then
    log "==> 服务未运行，尝试启动"
    systemctl start ayana.service 2>/dev/null || true
  fi
  log "  代码:     $PREFIX"
  log "  数据/DB:  $DB_PATH"
  log "  配置:     $CONFIG"
  log "  秘密:     $SECRETS"
  log "  日志:     $LOG_PATH"
  exit 0
fi

if [[ "$ENV_OK" -ne 1 ]]; then
  die "环境检查未通过，拒绝安装（或使用 --check 查看详情）"
fi

if [[ "$complete" -eq 1 && "$FORCE" -eq 1 ]]; then
  log "==> 检查通过但 --force，重新同步安装项"
fi

# ---------------------------------------------------------------------------
# 5) 只安装缺失项
# ---------------------------------------------------------------------------
log "==> 安装缺失项"

# --- 目录 ---
if [[ "$MODE" == "system" ]]; then
  if ! id ayana >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin ayana
    log "==> created system user ayana"
  else
    ok "system user ayana exists"
  fi
  install -d -o root -g ayana -m 750 "$PREFIX"
  install -d -o ayana -g ayana -m 750 "$DATA_DIR" "$DATA_DIR/log"
  install -d -o root -g ayana -m 750 "$CONF_DIR"
else
  install -d -m 700 "$PREFIX" "$DATA_DIR" "$DATA_DIR/log" "$CONF_DIR"
fi

# --- 代码（缺失才装；--force 才 --delete 同步）---
copy_tree() {
  local src="$1" dst="$2" delete_flag="$3"
  local rsync_opts=(-a)
  if [[ "$delete_flag" -eq 1 ]]; then
    rsync_opts+=(--delete)
  fi
  if command -v rsync >/dev/null 2>&1; then
    rsync "${rsync_opts[@]}" \
      --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
      --exclude 'secrets.json' --exclude 'config.json' \
      --exclude 'ayana.db*' --exclude '*.log' --exclude 'bootstrap-admin.password' \
      --exclude '.git/' --exclude '*.tar.gz' --exclude 'docs/reviews/' \
      --exclude '.pw-verify/' --exclude 'ui-*.png' \
      "$src/" "$dst/"
  else
    (cd "$src" && tar cf - \
      --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='secrets.json' --exclude='config.json' \
      --exclude='ayana.db*' --exclude='*.log' --exclude='bootstrap-admin.password' \
      --exclude='.git' --exclude='*.tar.gz' --exclude='docs/reviews' \
      .) | (cd "$dst" && tar xf -)
  fi
}

if [[ "$HAS_CODE" -eq 0 || "$FORCE" -eq 1 ]]; then
  log "==> installing code to $PREFIX"
  copy_tree "$ROOT" "$PREFIX" "$FORCE"
  if [[ "$MODE" == "system" ]]; then
    chown -R root:ayana "$PREFIX"
    find "$PREFIX" -type d -exec chmod 750 {} +
    find "$PREFIX" -type f -exec chmod u=rw,go=r {} +
    find "$PREFIX" -type f \( -name '*.sh' -o -path '*/bin/*' \) -exec chmod u=rwx,go=rx {} +
  fi
else
  ok "code already present, skip copy"
fi

# --- venv ---
if [[ "$HAS_VENV" -eq 0 ]]; then
  log "==> creating venv"
  "$PYTHON_BIN" -m venv "$VENV"
else
  ok "venv exists, skip create"
fi

if [[ "$SKIP_PIP" -eq 0 && ( "$HAS_DEPS" -eq 0 || "$FORCE" -eq 1 || "$HAS_VENV" -eq 0 ) ]]; then
  log "==> installing Python deps"
  "$VENV/bin/pip" install -U pip >/dev/null
  "$VENV/bin/pip" install -r "$PREFIX/requirements.txt"
else
  ok "deps present or --skip-pip, skip pip"
fi

if [[ "$MODE" == "system" ]]; then
  chown -R root:ayana "$VENV" || true
fi

# --- secrets（缺了才生成，不覆盖）---
if [[ "$HAS_SECRETS" -eq 1 ]]; then
  ok "secrets exists, keep $SECRETS"
else
  log "==> generating $SECRETS"
  "$VENV/bin/python" "$PREFIX/scripts/gen-secrets.py" -o "$SECRETS"
  if [[ "$MODE" == "system" ]]; then
    chown root:ayana "$SECRETS"
    chmod 640 "$SECRETS"
  else
    chmod 600 "$SECRETS"
  fi
fi

# --- config.json（缺了才写；已有配置绝不覆盖）---
if [[ "$HAS_CONFIG" -eq 1 ]]; then
  ok "config exists, keep $CONFIG"
else
  log "==> writing $CONFIG"
  cat >"$CONFIG" <<EOF
{
  "ws_host": "127.0.0.1",
  "ws_port": 6199,
  "ws_path": "/ws",
  "http_host": "$HTTP_HOST",
  "http_port": $HTTP_PORT,
  "log_level": "INFO",
  "log_file": "$LOG_PATH",
  "self_id": 0,
  "db_path": "$DB_PATH",
  "prometheus_url": "http://127.0.0.1:9090",
  "alertmanager_url": "http://127.0.0.1:9093",
  "admin_qq": "",
  "auto_remediation_enabled": false,
  "verify_window_sec": 90,
  "verify_timeout_sec": 300
}
EOF
  if [[ "$MODE" == "system" ]]; then
    chown root:ayana "$CONFIG"
    chmod 640 "$CONFIG"
  else
    chmod 600 "$CONFIG"
  fi
fi

# --- systemd（缺了或 --force 才写单元并重启）---
if [[ "$MODE" == "system" ]] && command -v systemctl >/dev/null 2>&1; then
  if [[ "$HAS_UNIT" -eq 1 && "$FORCE" -eq 0 ]]; then
    ok "unit exists, skip write"
  else
    log "==> installing systemd unit"
    cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Ayana ops agent (non-root)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ayana
Group=ayana
WorkingDirectory=$PREFIX
ExecStart=$VENV/bin/python -m ayana.main $CONFIG
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=20
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ayana.service
  fi
  if [[ "$HAS_ACTIVE" -eq 0 || "$FORCE" -eq 1 ]]; then
    log "==> (re)starting ayana.service"
    systemctl restart ayana.service
  else
    ok "service already active"
  fi
  log "==> systemd: systemctl status ayana"
fi

# --- 首启提示 ---
log ""
log "安装完成（只补齐了缺失项）。"
log "  代码:     $PREFIX"
log "  数据/DB:  $DB_PATH"
log "  配置:     $CONFIG"
log "  秘密:     $SECRETS"
log "  日志:     $LOG_PATH"
log ""
if [[ "$MODE" == "system" ]]; then
  log "下一步:"
  log "  1) systemctl status ayana"
  log "  2) journalctl -u ayana -n 50   # 找 BOOTSTRAP admin 与口令文件路径"
  log "  3) 浏览器打开 http://${HTTP_HOST}:${HTTP_PORT}  （或反代地址）"
  log "  4) 用 bootstrap 口令登录并强制改密，然后删除口令文件"
else
  log "下一步:"
  log "  1) $VENV/bin/python -m ayana.main $CONFIG"
  log "  2) 查看输出中的 BOOTSTRAP admin 与 bootstrap-admin.password 路径"
  log "  3) 浏览器打开 http://${HTTP_HOST}:${HTTP_PORT}"
  log "  4) 登录后改密并删除口令文件"
fi
log "NapCat/企微可选，不影响 Web 登录。"
log "重复执行本脚本：检查通过会直接跳过；需要重装请加 --force。"
