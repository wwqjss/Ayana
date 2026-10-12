#!/usr/bin/env bash
# Ayana 一键安装（Linux）
# - 代码目录只读 / 数据目录可写（DB、secrets、日志、bootstrap 口令）
# - secrets.json 自动生成，不覆盖已有文件
# - 可选安装 systemd 单元（--system）
#
# 用法：
#   bash deploy/install.sh --user                 # 当前用户（默认）
#   sudo bash deploy/install.sh --system          # 系统级 + systemd
#   sudo bash deploy/install.sh --system --prefix /opt/ayana --data /var/lib/ayana
set -euo pipefail

MODE="user"
PREFIX=""
DATA_DIR=""
CONF_DIR=""
HTTP_PORT="6200"
HTTP_HOST="127.0.0.1"
SKIP_PIP=0
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \?//'
  exit "${1:-0}"
}

log() { printf '%s\n' "$*"; }
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
    -h|--help) usage 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

# 脚本所在包/源码根目录
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$ROOT/ayana/main.py" ]] || die "run from extracted package (missing ayana/main.py)"
[[ -f "$ROOT/requirements.txt" ]] || die "missing requirements.txt"
command -v "$PYTHON_BIN" >/dev/null || die "python3 not found"

if [[ "$MODE" == "system" ]]; then
  [[ "$(id -u)" -eq 0 ]] || die "--system requires root"
  PREFIX="${PREFIX:-/opt/ayana}"
  DATA_DIR="${DATA_DIR:-/var/lib/ayana}"
  CONF_DIR="${CONF_DIR:-/etc/ayana}"
else
  PREFIX="${PREFIX:-$HOME/.local/share/ayana}"
  DATA_DIR="${DATA_DIR:-$HOME/.local/share/ayana-data}"
  CONF_DIR="${CONF_DIR:-$HOME/.config/ayana}"
fi

log "==> mode=$MODE"
log "    prefix (code) = $PREFIX"
log "    data          = $DATA_DIR"
log "    conf          = $CONF_DIR"

# --- 目录 ---
if [[ "$MODE" == "system" ]]; then
  if ! id ayana >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin ayana
    log "==> created system user ayana"
  fi
  install -d -o root -g ayana -m 750 "$PREFIX"
  install -d -o ayana -g ayana -m 750 "$DATA_DIR" "$DATA_DIR/log"
  install -d -o root -g ayana -m 750 "$CONF_DIR"
else
  install -d -m 700 "$PREFIX" "$DATA_DIR" "$DATA_DIR/log" "$CONF_DIR"
fi

# --- 代码同步（rsync 风格拷贝，不碰 secrets/db/log）---
copy_tree() {
  local src="$1" dst="$2"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
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
log "==> installing code to $PREFIX"
copy_tree "$ROOT" "$PREFIX"
if [[ "$MODE" == "system" ]]; then
  chown -R root:ayana "$PREFIX"
  # 目录可进入，文件默认 640；保留可执行位
  find "$PREFIX" -type d -exec chmod 750 {} +
  find "$PREFIX" -type f -exec chmod u=rw,go=r {} +
  find "$PREFIX" -type f \( -name '*.sh' -o -path '*/bin/*' \) -exec chmod u=rwx,go=rx {} +
fi

# --- venv ---
VENV="$PREFIX/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  log "==> creating venv"
  "$PYTHON_BIN" -m venv "$VENV"
fi
if [[ "$SKIP_PIP" -eq 0 ]]; then
  log "==> installing Python deps"
  "$VENV/bin/pip" install -U pip >/dev/null
  "$VENV/bin/pip" install -r "$PREFIX/requirements.txt"
fi
if [[ "$MODE" == "system" ]]; then
  chown -R root:ayana "$VENV" || true
fi

# --- secrets（自动生成，不覆盖）---
SECRETS="$CONF_DIR/secrets.json"
if [[ -f "$SECRETS" ]]; then
  log "==> secrets exists, keep $SECRETS"
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

# --- config.json ---
CONFIG="$CONF_DIR/config.json"
DB_PATH="$DATA_DIR/ayana.db"
LOG_PATH="$DATA_DIR/log/ayana.log"
if [[ -f "$CONFIG" ]]; then
  log "==> config exists, keep $CONFIG"
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

# --- systemd ---
if [[ "$MODE" == "system" ]] && command -v systemctl >/dev/null 2>&1; then
  log "==> installing systemd unit"
  cat >/etc/systemd/system/ayana.service <<EOF
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
  systemctl restart ayana.service
  log "==> systemd: systemctl status ayana"
fi

# --- 首启提示 ---
log ""
log "安装完成。"
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
