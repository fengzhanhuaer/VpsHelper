#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO_URL="https://github.com/fengzhanhuaer/VpsHelper"
REPO_URL="${1:-${REPO_URL:-${DEFAULT_REPO_URL}}}"
INSTALL_DIR="${2:-${INSTALL_DIR:-}}"
SERVICE_NAME="${SERVICE_NAME:-vpshelper}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "请使用 root 执行，例如：curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash"
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

install_python_venv_if_needed() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "检测到 apt，尝试安装 python3-venv..."
        apt-get update -y >/dev/null 2>&1 || true
        if apt-get install -y python3-venv; then
            return 0
        fi

        local pyver
        pyver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
        if [[ -n "${pyver}" ]]; then
            apt-get install -y "python${pyver}-venv" && return 0
        fi
        return 1
    fi

    return 1
}

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

create_venv() {
    if python3 -m venv .venv; then
        return 0
    fi

    echo "首次创建 venv 失败，尝试自动安装 venv 组件后重试..."
    if install_python_venv_if_needed && python3 -m venv .venv; then
        echo "venv 组件安装成功，已完成虚拟环境创建。"
        return 0
    fi

    echo "创建 venv 失败。请手动安装后重试："
    echo "  Debian/Ubuntu: apt-get install -y python3-venv"
    echo "  或按版本安装: apt-get install -y python3.x-venv"
    return 1
}

if [[ -d ".venv" && ! -f ".venv/bin/activate" ]]; then
    echo "检测到损坏的虚拟环境，正在重建..."
    rm -rf .venv
fi

if [[ ! -f ".venv/bin/activate" ]]; then
    echo "创建虚拟环境..."
    create_venv || exit 1
fi

source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

FLASK_SECRET_KEY_VALUE="${FLASK_SECRET_KEY:-}"
if [[ -z "${FLASK_SECRET_KEY_VALUE}" ]]; then
    FLASK_SECRET_KEY_VALUE="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
fi

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
Environment=TZ=Asia/Shanghai
Environment=FLASK_SECRET_KEY=${FLASK_SECRET_KEY_VALUE}
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
echo "最近 50 行服务日志 (${SERVICE_NAME})："
if command -v journalctl >/dev/null 2>&1; then
    journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager || true
else
    echo "当前系统无 journalctl，可使用 systemctl status ${SERVICE_NAME}.service 查看日志。"
fi

echo ""
echo "安装完成，服务已启动: ${SERVICE_NAME}"
echo "默认访问: http://127.0.0.1:15018"
