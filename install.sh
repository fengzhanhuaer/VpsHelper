#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO_URL="https://github.com/fengzhanhuaer/VpsHelper"
REPO_URL="${1:-${REPO_URL:-${DEFAULT_REPO_URL}}}"
INSTALL_DIR="${2:-${INSTALL_DIR:-}}"
SERVICE_NAME="${SERVICE_NAME:-vpshelper}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "请使用 root 执行，例如：curl -fsSL https://raw.githubusercontent.com/fengzhanhuaer/VpsHelper/main/install.sh | sudo bash"
    exit 1
fi

if [[ -z "${INSTALL_DIR}" ]]; then
    INSTALL_DIR="/opt/${SERVICE_NAME}"
fi

RUN_USER="${RUN_USER:-${SUDO_USER:-root}}"

ensure_command() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "缺少命令: ${cmd}"
        if [[ -n "${hint}" ]]; then
            echo "提示: ${hint}"
        fi
        exit 1
    fi
}

ensure_command git "请先用系统包管理器安装 git"
ensure_command python3 "请先用系统包管理器安装 python3"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo "更新仓库: ${INSTALL_DIR}"
    git -C "${INSTALL_DIR}" fetch --prune
    git -C "${INSTALL_DIR}" pull --rebase
else
    echo "克隆仓库到: ${INSTALL_DIR}"
    rm -rf "${INSTALL_DIR}"
    git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

if [[ ! -d ".venv" ]]; then
    echo "创建虚拟环境..."
    if ! python3 -m venv .venv; then
        echo "创建 venv 失败。Debian/Ubuntu 可先执行: apt-get install -y python3-venv"
        exit 1
    fi
fi

source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=VpsHelper Service
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=TGHELPER_DEV=1
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/VpsHelper.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

chown -R "${RUN_USER}:${RUN_USER}" "${INSTALL_DIR}"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"
systemctl status "${SERVICE_NAME}.service" --no-pager

echo ""
echo "安装完成，服务已启动: ${SERVICE_NAME}"
echo "默认访问: http://127.0.0.1:15018"
