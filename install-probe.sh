#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO="fengzhanhuaer/VpsHelper"
REPO_SLUG=""
INSTALL_DIR="/opt/vpsprobe"
SERVICE_NAME="vpsprobe"
BINARY_NAME="vpsprobe"

PROBE_SECRET=""
PROBE_HOST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --secret) PROBE_SECRET="$2"; shift 2 ;;
    --host) PROBE_HOST="$2"; shift 2 ;;
    --repo) REPO_SLUG="$2"; shift 2 ;;
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    -*) echo "未知参数: $1"; exit 1 ;;
    *) shift ;;
  esac
done

REPO_SLUG="${REPO_SLUG:-$DEFAULT_REPO}"

if [[ -z "$PROBE_SECRET" ]] || [[ -z "$PROBE_HOST" ]]; then
  echo "安装探针必须同时指定 --secret 和 --host"
  echo "例如: curl -sSL https://.../install-probe.sh | bash -s -- --secret XXX --host https://... "
  exit 1
fi

RUN_USER="${SUDO_USER:-root}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 权限执行此脚步。"
  exit 1
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

    if ! curl "${curl_opts[@]}" -C - -o "${dest}" "${url}"; then
      rm -f "${dest}" || true
      curl "${curl_opts[@]}" -o "${dest}" "${url}"
    fi
  else
    wget -c -O "${dest}" --tries="${DOWNLOAD_RETRY}" --timeout="${DOWNLOAD_CONNECT_TIMEOUT}" --waitretry=2 --retry-connrefused "${url}"
  fi

  if ! is_elf_file "${dest}"; then
    echo "下载结果看起来不是可执行 ELF 文件（可能下载到错误页面或文件损坏）。"
    exit 1
  fi
}

ensure_command systemctl "需要 systemd (systemctl) 才能一键安装为服务"

disable_service_if_exists() {
  local svc="$1"
  if systemctl cat "${svc}.service" >/dev/null 2>&1; then
    echo "检测到已有探针服务：${svc}.service，正在停止并禁用..."
    systemctl disable --now "${svc}.service" >/dev/null 2>&1 || true
  fi
}

disable_service_if_exists "${SERVICE_NAME}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

case "$os" in
  linux) goos="linux" ;;
  *) echo "暂不支持该系统: $os"; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) goarch="amd64" ;;
  *) echo "暂不支持该架构: $arch (目前探针仅打包 AMD64 Linux)"; exit 1 ;;
esac

asset="${BINARY_NAME}_${goos}_${goarch}"
url="https://github.com/${REPO_SLUG}/releases/latest/download/${asset}"

mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/userdata"
bin_path="${INSTALL_DIR}/bin/${BINARY_NAME}"

tmp="${bin_path}.download"
mkdir -p "$(dirname "${tmp}")"

echo "下载探针 Release: ${url}"
download_release "${url}" "$tmp"

chmod 755 "$tmp"
mv -f "$tmp" "$bin_path"

service_file="/etc/systemd/system/${SERVICE_NAME}.service"
cat >"$service_file" <<EOF
[Unit]
Description=VpsProbe (Agent) Service
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${bin_path} -host ${PROBE_HOST} -secret ${PROBE_SECRET}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chown -R "${RUN_USER}:${RUN_USER}" "${INSTALL_DIR}"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo ""
echo "探针服务状态:"
systemctl status "${SERVICE_NAME}.service" --no-pager || true

echo ""
echo "最近 50 行日志:"
journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager || true

echo ""
echo "探针安装完成！程序已在此后台静默运行中并连接至 ${PROBE_HOST}。"
