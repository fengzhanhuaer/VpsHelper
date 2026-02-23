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
  echo "请使用 root 执行，例如：curl -fsSL https://github.com/${REPO_SLUG}/raw/refs/heads/main/install.sh | sudo bash"
  exit 1
fi

if [[ -z "${INSTALL_DIR}" ]]; then
  INSTALL_DIR="/opt/vpshelper"
fi

if [[ "${1:-}" == "uninstall" ]]; then
  echo "正在卸载 ${SERVICE_NAME}..."
  systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
  systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload
  rm -rf "${INSTALL_DIR}"
  echo "卸载完成！"
  exit 0
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

DOWNLOAD_RETRY="${VPSHELPER_DOWNLOAD_RETRY:-8}"
DOWNLOAD_CONNECT_TIMEOUT="${VPSHELPER_DOWNLOAD_CONNECT_TIMEOUT:-15}"
DOWNLOAD_MAX_TIME="${VPSHELPER_DOWNLOAD_MAX_TIME:-900}"

curl_supports() {
  local opt="$1"
  curl --help all 2>/dev/null | grep -q -- "${opt}" || curl --help 2>/dev/null | grep -q -- "${opt}"
}

is_elf_file() {
  local p="$1"
  [[ -f "${p}" ]] || return 1
  [[ -s "${p}" ]] || return 1
  # 7f 45 4c 46 => \x7fELF
  local magic
  magic="$(dd if="${p}" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  [[ "${magic}" == "7f454c46" ]]
}

download_release() {
  local url="$1"
  local dest="$2"

  if [[ "${DOWNLOADER}" == "curl" ]]; then
    local -a curl_opts
    curl_opts=(-fL --retry "${DOWNLOAD_RETRY}" --retry-delay 2 --connect-timeout "${DOWNLOAD_CONNECT_TIMEOUT}" --max-time "${DOWNLOAD_MAX_TIME}")
    if curl_supports "--retry-connrefused"; then curl_opts+=(--retry-connrefused); fi
    if curl_supports "--retry-all-errors"; then curl_opts+=(--retry-all-errors); fi

    # First try: resume if partial exists.
    if ! curl "${curl_opts[@]}" -C - -o "${dest}" "${url}"; then
      # If range/resume fails or file is corrupted, retry once from scratch.
      rm -f "${dest}" || true
      curl "${curl_opts[@]}" -o "${dest}" "${url}"
    fi
  else
    # wget: -c enables resume; add conservative timeouts/retries.
    wget -c -O "${dest}" --tries="${DOWNLOAD_RETRY}" --timeout="${DOWNLOAD_CONNECT_TIMEOUT}" --waitretry=2 --retry-connrefused "${url}"
  fi

  if ! is_elf_file "${dest}"; then
    echo "下载结果看起来不是可执行 ELF 文件（可能下载到错误页面或文件损坏）。"
    echo "你可以重试，或设置更长超时：VPSHELPER_DOWNLOAD_MAX_TIME=1800"
    exit 1
  fi
}

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

# Replace legacy service by default.
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

if [[ -d "${INSTALL_DIR}/.venv" ]]; then
  echo "Detected legacy runtime files under ${INSTALL_DIR}. Existing files are kept, service will be switched to Go binary."
fi

bin_path="${INSTALL_DIR}/bin/vpshelper"

tmp="${bin_path}.download"
mkdir -p "$(dirname "${tmp}")"

echo "下载 Release: ${url}"
download_release "${url}" "$tmp"

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
