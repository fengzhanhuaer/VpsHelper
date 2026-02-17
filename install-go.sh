#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO="fengzhanhuaer/VpsHelper"
REPO_SLUG="${REPO_SLUG:-${1:-$DEFAULT_REPO}}"
INSTALL_DIR="${INSTALL_DIR:-${2:-}}"
SERVICE_NAME="${SERVICE_NAME:-vpshelper}"
RUN_USER="${RUN_USER:-${SUDO_USER:-root}}"
LISTEN_ADDR="${VPSHELPER_LISTEN:-:15018}"
TZ_VALUE="${TZ:-Asia/Shanghai}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 执行，例如：curl -fsSL https://github.com/${REPO_SLUG}/raw/refs/heads/main/install-go.sh | sudo bash"
  exit 1
fi

if [[ -z "${INSTALL_DIR}" ]]; then
  INSTALL_DIR="/opt/vpshelper"
fi

ensure_command() {
  local cmd="$1"
  local hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "缺少命令: $cmd"
    [[ -n "$hint" ]] && echo "提示: $hint"
    exit 1
  fi
}

if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  echo "缺少 curl 或 wget"
  exit 1
fi

ensure_command systemctl "需要 systemd (systemctl) 才能一键安装为服务"

disable_service_if_exists() {
  local svc="$1"
  if systemctl cat "${svc}.service" >/dev/null 2>&1; then
    echo "检测到已有服务：${svc}.service，正在停止并禁用..."
    systemctl disable --now "${svc}.service" >/dev/null 2>&1 || true
  fi
}

backup_unit_if_exists() {
  local svc="$1"
  local unit_file="/etc/systemd/system/${svc}.service"
  if [[ -f "${unit_file}" ]]; then
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local bak="${unit_file}.bak.${ts}"
    echo "备份已有 unit：${unit_file} -> ${bak}"
    cp -f "${unit_file}" "${bak}" || true
  fi
}

# Replace legacy Python service by default.
if [[ "${SERVICE_NAME}" == "vpshelper" ]]; then
  disable_service_if_exists "vpshelper-go"
else
  disable_service_if_exists "vpshelper"
fi

# Stop target service before replacing binary/unit.
disable_service_if_exists "${SERVICE_NAME}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

case "$os" in
  linux) goos="linux" ;;
  *) echo "暂不支持该系统: $os"; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  *) echo "暂不支持该架构: $arch"; exit 1 ;;
esac

asset="vpshelper_${goos}_${goarch}"
url="https://github.com/${REPO_SLUG}/releases/latest/download/${asset}"

mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/userdata"

if [[ -d "${INSTALL_DIR}/.venv" || -f "${INSTALL_DIR}/VpsHelper.py" ]]; then
  echo "检测到旧版 Python 安装内容位于 ${INSTALL_DIR}，将保留文件不删除（仅替换 systemd 服务与 Go 二进制）。"
fi

bin_path="${INSTALL_DIR}/bin/vpshelper"

tmp="${bin_path}.download"
rm -f "$tmp"

echo "下载 Release: ${url}"
if [[ "$DOWNLOADER" == "curl" ]]; then
  curl -fL --retry 3 --connect-timeout 10 --max-time 120 -o "$tmp" "$url"
else
  wget -O "$tmp" "$url"
fi

chmod 755 "$tmp"

# Replace binary atomically.
mv -f "$tmp" "$bin_path"

# Session key
session_key_file="${INSTALL_DIR}/session_key.txt"
if [[ ! -f "$session_key_file" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 >"$session_key_file"
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$session_key_file"
  fi
  chmod 600 "$session_key_file"
fi
session_key="$(tr -d '\r\n' <"$session_key_file")"

service_file="/etc/systemd/system/${SERVICE_NAME}.service"
backup_unit_if_exists "${SERVICE_NAME}"
cat >"$service_file" <<EOF
[Unit]
Description=VpsHelper (Go) Service
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=TZ=${TZ_VALUE}
Environment=VPSHELPER_LISTEN=${LISTEN_ADDR}
Environment=VPSHELPER_DATA_DIR=${INSTALL_DIR}/userdata
Environment=VPSHELPER_SESSION_KEY=${session_key}
ExecStart=${bin_path}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

chown -R "${RUN_USER}:${RUN_USER}" "${INSTALL_DIR}"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo ""
echo "服务状态:"
systemctl status "${SERVICE_NAME}.service" --no-pager || true

echo ""
echo "最近 50 行日志:"
journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager || true

echo ""
echo "安装完成。默认访问: http://127.0.0.1:15018"
