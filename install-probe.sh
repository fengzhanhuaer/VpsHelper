#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO="fengzhanhuaer/VpsHelper"
REPO_SLUG=""
INSTALL_DIR="/opt/vpsprobe"
SERVICE_NAME="vpsprobe"
BINARY_NAME="vpsprobe"

OFFLINE_MODE=0

show_menu() {
  while true; do
    echo "======================================"
    echo "         VpsProbe 探针管理菜单        "
    echo "======================================"
    echo "1. 安装/更新 探针服务 (在线下载)"
    echo "2. 离线安装 探针服务 (从当前目录读取)"
    echo "3. 查看探针运行状态 (systemctl status)"
    echo "4. 查看探针实时日志 (journalctl -f)  "
    echo "5. 重启探针服务"
    echo "6. 停止探针服务"
    echo "0. 退出菜单"
    echo "======================================"
    if ! read -rp "请输入对应的数字 [0-6]: " choice </dev/tty; then
      echo "无法打开交互终端，自动退出菜单。"
      exit 0
    fi
    case "$choice" in
      1)
        OFFLINE_MODE=0
        echo "开始执行在线安装/更新流程..."
        break
        ;;
      2)
        OFFLINE_MODE=1
        echo "开始执行离线安装流程..."
        break
        ;;
      3)
        if [[ "$INITSYS" == "systemd" ]]; then
          systemctl status "${SERVICE_NAME}.service" --no-pager || true
        elif [[ "$INITSYS" == "openrc" ]]; then
          rc-service "${SERVICE_NAME}" status || true
        fi
        ;;
      4)
        echo "按 Ctrl+C 退出日志查看..."
        if [[ "$INITSYS" == "systemd" ]]; then
          journalctl -u "${SERVICE_NAME}.service" -f || true
        elif [[ "$INITSYS" == "openrc" ]]; then
          tail -f "/var/log/${SERVICE_NAME}.err" "/var/log/${SERVICE_NAME}.log" || true
        fi
        ;;
      5)
        if [[ "$INITSYS" == "systemd" ]]; then
          systemctl restart "${SERVICE_NAME}.service"
        elif [[ "$INITSYS" == "openrc" ]]; then
          rc-service "${SERVICE_NAME}" restart
        fi
        echo "已重启探针服务。"
        ;;
      6)
        if [[ "$INITSYS" == "systemd" ]]; then
          systemctl stop "${SERVICE_NAME}.service"
        elif [[ "$INITSYS" == "openrc" ]]; then
          rc-service "${SERVICE_NAME}" stop
        fi
        echo "已停止探针服务。"
        ;;
      0)
        echo "退出菜单。"
        exit 0
        ;;
      *)
        echo "无效选择，请输入 0-6 之间的数字。"
        ;;
    esac
    echo ""
  done
}

PROBE_SECRET=""
PROBE_HOST=""
MENU_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --secret) PROBE_SECRET="$2"; shift 2 ;;
    --host) PROBE_HOST="$2"; shift 2 ;;
    --repo) REPO_SLUG="$2"; shift 2 ;;
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    menu|--menu) MENU_ONLY=1; shift ;;
    -*) echo "未知参数: $1"; exit 1 ;;
    *) shift ;;
  esac
done

if [[ "$MENU_ONLY" == "1" ]]; then
  show_menu
fi

REPO_SLUG="${REPO_SLUG:-$DEFAULT_REPO}"

if [[ -z "$PROBE_SECRET" ]] && [[ "$MENU_ONLY" == "1" ]]; then
  read -rp "请输入为您分配的探针节点密钥 (--secret): " PROBE_SECRET </dev/tty || true
fi
if [[ -z "$PROBE_HOST" ]] && [[ "$MENU_ONLY" == "1" ]]; then
  read -rp "请输入主控端访问地址 (--host, 如 https://example.com): " PROBE_HOST </dev/tty || true
fi

if [[ -z "$PROBE_SECRET" ]] || [[ -z "$PROBE_HOST" ]]; then
  echo "错误：安装探针必须提供 --secret 和 --host"
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

  local auth_header=""
  if [[ -n "${PROBE_SECRET}" && "${url}" == *"/api/probe/latest_binary"* ]]; then
    auth_header="Authorization: Bearer ${PROBE_SECRET}"
  fi

  if [[ "${DOWNLOADER}" == "curl" ]]; then
    local -a curl_opts
    curl_opts=(-fL --retry "${DOWNLOAD_RETRY}" --retry-delay 2 --connect-timeout "${DOWNLOAD_CONNECT_TIMEOUT}" --max-time "${DOWNLOAD_MAX_TIME}")
    if curl_supports "--retry-connrefused"; then curl_opts+=(--retry-connrefused); fi
    if curl_supports "--retry-all-errors"; then curl_opts+=(--retry-all-errors); fi
    if [[ -n "$auth_header" ]]; then curl_opts+=("-H" "${auth_header}"); fi

    if ! curl "${curl_opts[@]}" -C - -o "${dest}" "${url}"; then
      rm -f "${dest}" || true
      curl "${curl_opts[@]}" -o "${dest}" "${url}"
    fi
  else
    local -a wget_opts
    wget_opts=(-c -O "${dest}" --tries="${DOWNLOAD_RETRY}" --timeout="${DOWNLOAD_CONNECT_TIMEOUT}" --waitretry=2 --retry-connrefused)
    if [[ -n "$auth_header" ]]; then wget_opts+=("--header=${auth_header}"); fi
    
    wget "${wget_opts[@]}" "${url}"
  fi

  if ! is_elf_file "${dest}"; then
    echo "下载结果看起来不是可执行 ELF 文件（可能下载到错误页面或文件损坏）。"
    exit 1
  fi
}

INITSYS=""
if command -v systemctl >/dev/null 2>&1; then
  INITSYS="systemd"
elif command -v rc-service >/dev/null 2>&1; then
  INITSYS="openrc"
else
  echo "当前系统既没有发现 systemd (systemctl) 也没有 openrc (rc-service)。"
  echo "请手动将命令 ${INSTALL_DIR}/bin/${BINARY_NAME} -host ${PROBE_HOST} -secret ${PROBE_SECRET} 加入开机自启。"
  exit 1
fi

disable_service_if_exists() {
  local svc="$1"
  if [[ "$INITSYS" == "systemd" ]]; then
    if systemctl cat "${svc}.service" >/dev/null 2>&1; then
      echo "检测到已有探针服务：${svc}.service，正在停止并禁用..."
      systemctl disable --now "${svc}.service" >/dev/null 2>&1 || true
    fi
  elif [[ "$INITSYS" == "openrc" ]]; then
    if rc-service "${svc}" status >/dev/null 2>&1 || [[ -f "/etc/init.d/${svc}" ]]; then
      echo "检测到已有探针服务：${svc}，正在停止并禁用..."
      rc-service "${svc}" stop >/dev/null 2>&1 || true
      rc-update del "${svc}" >/dev/null 2>&1 || true
    fi
  fi
}

disable_service_if_exists "${SERVICE_NAME}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

case "$os" in
  linux) goos="linux" ;;
  darwin) goos="darwin" ;;
  *) echo "无法识别的操作系统: $os"; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  armv7l|armv6l|arm) goarch="arm" ;;
  i386|i686) goarch="386" ;;
  *) echo "暂不支持该架构: $arch"; exit 1 ;;
esac

asset="${BINARY_NAME}_${goos}_${goarch}"

# Try to download from the master proxy instead of raw github URL directly
if [[ -n "${PROBE_HOST}" ]]; then
  # Try to form proxy url
  clean_host="${PROBE_HOST%/}"
  url="${clean_host}/api/probe/latest_binary?os=${goos}&arch=${goarch}"
else
  url="https://github.com/${REPO_SLUG}/releases/latest/download/${asset}"
fi

mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/userdata"
bin_path="${INSTALL_DIR}/bin/${BINARY_NAME}"

tmp="${bin_path}.download"
mkdir -p "$(dirname "${tmp}")"

if [[ "$OFFLINE_MODE" == "1" ]]; then
  local_file=""
  if [[ -f "./${asset}" ]]; then
    local_file="./${asset}"
  elif [[ -f "./vpsprobe" ]]; then
    local_file="./vpsprobe"
  fi
  
  if [[ -z "$local_file" ]]; then
    echo "错误：当前目录 ($(pwd)) 未找到离线安装包！"
    echo "请将下载好的 ${asset} 或 vpsprobe 放到此目录后重试。"
    exit 1
  fi
  
  echo "正在使用本地包进行离线安装: ${local_file}"
  cp -f "$local_file" "$tmp"
else
  echo "下载探针 Release: ${url}"
  download_release "${url}" "$tmp"
fi

chmod 755 "$tmp"

backup_path="${bin_path}.backup"
has_backup=0

if [[ -f "$bin_path" ]]; then
  echo "发现旧版探针可执行文件，正在备份: ${bin_path} -> ${backup_path}"
  cp -f "$bin_path" "$backup_path"
  has_backup=1
fi

mv -f "$tmp" "$bin_path"


if [[ "$INITSYS" == "systemd" ]]; then
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
  systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1
  echo "正在启动当前探针服务并进行状态健康检查..."
  systemctl restart "${SERVICE_NAME}.service"

  sleep 3
  if ! systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    echo "======================================"
    echo "错误: 探针安装/升级后进程启动失败！"
    if [[ $has_backup -eq 1 ]]; then
      echo "正在触发回滚机制恢复前一个版本..."
      mv -f "$backup_path" "$bin_path"
      systemctl restart "${SERVICE_NAME}.service"
      if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        echo "回滚成功，已恢复到旧版本进程并重启！"
      else
        echo "回滚后仍启动失败，请查阅日志详情: journalctl -fu ${SERVICE_NAME}.service"
      fi
    else
      echo "无可用旧版本执行档用于回滚。请查阅系统日志: journalctl -fu ${SERVICE_NAME}.service"
    fi
    echo "======================================"
    exit 1
  else
    echo "✅ 探针进程启动/运行健康，安装/更新完成。"
  fi

elif [[ "$INITSYS" == "openrc" ]]; then
  service_file="/etc/init.d/${SERVICE_NAME}"
  cat >"$service_file" <<EOF
#!/sbin/openrc-run

name="VpsProbe (Agent) Service"
description="VPS Helper Agent Node"
command="${bin_path}"
command_args="-host ${PROBE_HOST} -secret ${PROBE_SECRET}"
command_background="yes"
pidfile="/run/${SERVICE_NAME}.pid"
output_log="/var/log/${SERVICE_NAME}.log"
error_log="/var/log/${SERVICE_NAME}.err"
directory="${INSTALL_DIR}"
command_user="${RUN_USER}:${RUN_USER}"

depend() {
        need net
}
EOF

  chown -R "${RUN_USER}:${RUN_USER}" "${INSTALL_DIR}"
  chmod +x "$service_file"

  rc-update add "${SERVICE_NAME}" default >/dev/null 2>&1
  echo "正在启动当前探针服务并进行状态健康检查..."
  rc-service "${SERVICE_NAME}" restart

  sleep 3
  if ! rc-service "${SERVICE_NAME}" status | grep -q 'started'; then
    echo "======================================"
    echo "错误: 探针进程启动失败！"
    if [[ $has_backup -eq 1 ]]; then
      echo "正在触发回滚机制..."
      mv -f "$backup_path" "$bin_path"
      rc-service "${SERVICE_NAME}" restart
      if rc-service "${SERVICE_NAME}" status | grep -q 'started'; then
        echo "回滚成功！"
      fi
    fi
    echo "请检查 /var/log/${SERVICE_NAME}.err"
    echo "======================================"
    exit 1
  else
    echo "✅ 探针进程启动/运行健康，安装/更新完成。"
  fi
fi

echo ""
echo "探针安装/更新完成！程序目前由后台服务自动托管运行，已连接至 ${PROBE_HOST}。"
show_menu
