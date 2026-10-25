#!/usr/bin/env bash
# Ayana-SpeedSupreme 一键部署 / 更新 / 回滚（Linux）
#
# 用法：
#   sudo bash deploy/ayana-setup.sh init    --git <url> [--branch speed-supreme]
#        [--prefix /opt/ayana] [--data /var/lib/ayana] [--conf /etc/ayana]
#        [--user ayana] [--http-port 6200] [--ws-port 6199]
#   sudo bash deploy/ayana-setup.sh update  [--ref origin/speed-supreme]
#   sudo bash deploy/ayana-setup.sh rollback
#   sudo bash deploy/ayana-setup.sh status
#   sudo bash deploy/ayana-setup.sh health
#
# 敏感配置（secrets.json / config.json）永不写入 Git；脚本只生成本地文件。
# update 前自动备份当前代码到 $PREFIX/.releases/<ts>，rollback 恢复上一份。
set -euo pipefail

CMD="${1:-help}"
shift || true

GIT_URL=""
GIT_REF="speed-supreme"
PREFIX="/opt/ayana"
DATA_DIR="/var/lib/ayana"
CONF_DIR="/etc/ayana"
SVC_USER="ayana"
HTTP_PORT="6200"
WS_PORT="6199"
PY="${PYTHON_BIN:-python3}"
SVC_NAME="ayana"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --git) GIT_URL="${2:?}"; shift 2 ;;
    --branch|--ref) GIT_REF="${2:?}"; shift 2 ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --data) DATA_DIR="${2:?}"; shift 2 ;;
    --conf) CONF_DIR="${2:?}"; shift 2 ;;
    --user) SVC_USER="${2:?}"; shift 2 ;;
    --http-port) HTTP_PORT="${2:?}"; shift 2 ;;
    --ws-port) WS_PORT="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# systemd unit name follows install prefix so sandbox does not clash with prod
SVC_NAME="$(basename "$PREFIX")"
[[ "$SVC_NAME" == "ayana" ]] || SVC_NAME="ayana-$SVC_NAME"

log()  { printf '[ayana-setup] %s\n' "$*"; }
die()   { printf '[ayana-setup] ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  [[ $EUID -eq 0 ]] || die "need root (sudo)"
}

gen_secrets() {
  local f="$1"
  if [[ -s "$f" ]]; then
    log "keep existing secrets: $f"
    return 0
  fi
  umask 077
  local tok wh pepper skey
  tok=$($PY -c "import secrets;print(secrets.token_urlsafe(32))")
  wh=$($PY -c "import secrets;print(secrets.token_urlsafe(24))")
  pepper=$($PY -c "import secrets;print(secrets.token_urlsafe(16))")
  skey=$($PY -c "import secrets;print(secrets.token_urlsafe(32))")
  cat >"$f" <<EOF
{
  "onewbot_token": "$tok",
  "webhook_token": "$wh",
  "web_auth_pepper": "$pepper",
  "ssh_credential_key": "$skey"
}
EOF
  chmod 600 "$f"
  log "generated secrets: $f"
}

write_config() {
  local f="$1"
  if [[ -s "$f" ]]; then
    log "keep existing config: $f"
    return 0
  fi
  cat >"$f" <<EOF
{
  "ws_host": "0.0.0.0",
  "ws_port": $WS_PORT,
  "ws_path": "/ws",
  "http_host": "0.0.0.0",
  "http_port": $HTTP_PORT,
  "log_level": "INFO",
  "log_file": "$DATA_DIR/ayana.log",
  "self_id": 0,
  "db_path": "$DATA_DIR/ayana.db",
  "prometheus_url": "http://127.0.0.1:9090",
  "alertmanager_url": "http://127.0.0.1:9093",
  "alertmanager_webhook_path": "/hooks/alertmanager",
  "legacy_agent_loop": false,
  "auto_remediation_enabled": false,
  "auto_investigate": { "enabled": false }
}
EOF
  chmod 640 "$f"
  log "generated config: $f"
}

write_unit() {
  local unit="/etc/systemd/system/${SVC_NAME}.service"
  cat >"$unit" <<EOF
[Unit]
Description=Ayana ops agent ($SVC_NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$PREFIX
ExecStart=$PREFIX/.venv/bin/python -m ayana.main $CONF_DIR/config.json
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=20
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR $CONF_DIR /var/log/ayana

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  log "systemd unit written: $unit"
}

health() {
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/health" || echo 000)
  if [[ "$code" == "200" ]]; then
    log "health OK (HTTP $code)"
    systemctl is-active "$SVC_NAME"
    return 0
  fi
  log "health FAIL (HTTP $code)"
  systemctl is-active "$SVC_NAME" || true
  journalctl -u "$SVC_NAME" -n 20 --no-pager || true
  return 1
}

backup_release() {
  local ts rel
  ts=$(date +%Y%m%d-%H%M%S)
  rel="$PREFIX/.releases/$ts"
  mkdir -p "$PREFIX/.releases"
  mkdir -p "$rel"
  for item in ayana knowledge scripts pyproject.toml; do
    if [[ -e "$PREFIX/$item" ]]; then
      cp -a "$PREFIX/$item" "$rel/"
    fi
  done
  echo "$rel" > "$PREFIX/.releases/LAST"
  log "backed up to $rel"
}

cmd_init() {
  need_root
  [[ -n "$GIT_URL" ]] || die "--git <url> required"
  log "init prefix=$PREFIX data=$DATA_DIR conf=$CONF_DIR user=$SVC_USER"

  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
  mkdir -p "$PREFIX" "$DATA_DIR" "$CONF_DIR" /var/log/ayana
  chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR" /var/log/ayana

  if [[ -d "$PREFIX/.git" ]]; then
    log "git repo exists, fetch/update"
    git -C "$PREFIX" fetch --all
    git -C "$PREFIX" checkout "$GIT_REF"
    git -C "$PREFIX" pull --ff-only || true
  else
    log "clone $GIT_URL ($GIT_REF)"
    git clone --branch "$GIT_REF" "$GIT_URL" "$PREFIX"
  fi

  if [[ ! -d "$PREFIX/.venv" ]]; then
    "$PY" -m venv "$PREFIX/.venv"
  fi
  "$PREFIX/.venv/bin/pip" install -U pip wheel >/dev/null
  "$PREFIX/.venv/bin/pip" install -e "$PREFIX"

  write_config "$CONF_DIR/config.json"
  gen_secrets "$CONF_DIR/secrets.json"
  chown -R "$SVC_USER:$SVC_USER" "$PREFIX/ayana" "$PREFIX/knowledge" 2>/dev/null || true
  chown "$SVC_USER:$SVC_USER" "$CONF_DIR/config.json" "$CONF_DIR/secrets.json"
  chmod 600 "$CONF_DIR/secrets.json"

  write_unit
  systemctl enable --now "$SVC_NAME"
  sleep 2
  health || die "init finished but health failed"
  log "init complete"
}

cmd_update() {
  need_root
  [[ -d "$PREFIX/.git" ]] || die "not a git install: $PREFIX"
  backup_release
  git -C "$PREFIX" fetch --all
  git -C "$PREFIX" checkout "$GIT_REF"
  git -C "$PREFIX" pull --ff-only || log "pull ff-only skipped (local ref)"
  "$PREFIX/.venv/bin/pip" install -e "$PREFIX" >/dev/null
  systemctl restart "$SVC_NAME"
  sleep 2
  if ! health; then
    log "update health failed — rolling back"
    cmd_rollback
    die "update rolled back"
  fi
  log "update complete"
}

cmd_rollback() {
  need_root
  local rel
  rel=$(cat "$PREFIX/.releases/LAST" 2>/dev/null || true)
  [[ -n "$rel" && -d "$rel" ]] || die "no backup to rollback"
  log "rollback from $rel"
  for item in ayana knowledge scripts; do
    rm -rf "$PREFIX/$item"
    [[ -e "$rel/$item" ]] && cp -a "$rel/$item" "$PREFIX/"
  done
  [[ -e "$rel/pyproject.toml" ]] && cp -a "$rel/pyproject.toml" "$PREFIX/"
  "$PREFIX/.venv/bin/pip" install -e "$PREFIX" >/dev/null || true
  systemctl restart "$SVC_NAME"
  sleep 2
  health || die "rollback health failed"
  log "rollback complete"
}

cmd_status() {
  echo "prefix=$PREFIX data=$DATA_DIR conf=$CONF_DIR"
  git -C "$PREFIX" log --oneline -3 2>/dev/null || echo "git: n/a"
  systemctl is-active "$SVC_NAME" || true
  ls -la "$CONF_DIR" 2>/dev/null || true
  echo "--- releases ---"
  ls -la "$PREFIX/.releases" 2>/dev/null | tail -5 || true
}

case "$CMD" in
  init) cmd_init ;;
  update) cmd_update ;;
  rollback) cmd_rollback ;;
  status) cmd_status ;;
  health) need_root; health ;;
  help|-h|--help) sed -n '2,18p' "$0" | sed 's/^# \?//' ;;
  *) die "unknown command: $CMD" ;;
esac
