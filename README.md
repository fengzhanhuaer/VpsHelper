# VpsHelper

VpsHelper is a powerful, lightweight, Go-based (Gin + SQLite/Cloudflare D1) server management and Telegram Bot integration toolkit.

## Features

- **Web Dashboard**: Modern UI with dark/light mode, mobile-friendly interface for managing your server.
- **Telegram Helper**: Manage Telegram userbots (MTProto via `gotd`), check sessions, auto-sign, auto-reply, auto-send tasks.
- **Telegram Bot Control**: Connect a private Telegram Bot to securely receive webhooks and send commands (like `/ping`, `/status`) directly to your VPS.
- **Auto Backups (Cloudflare D1)**: Automatically sync and backup your SQLite database to Cloudflare D1. 
- **Web Terminal (Shell)**: Execute predefined safe commands or arbitrary shell commands directly from the dashboard.
- **SSH & Firewall**: View active SSH sessions, ban IP rules (using `ufw`/`iptables`), and manage SSH server keys.
- **One-Click Update**: Auto-check for the newest releases on GitHub, perform a pre-flight smoke test, and seamlessly seamlessly replace and restart the service without downtime.

## Setup & Deployment

### Run locally (Development)

**Windows** (PowerShell):
```powershell
.\VpsHelper.bat
# or
cd goapp
go run ./cmd/server
```

**Linux/macOS**:
```bash
chmod +x VpsHelper.sh
./VpsHelper.sh
# or
cd goapp
go run ./cmd/server
```

### Install as Linux service (Production)

Recommended one-click install and upgrade command:

```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash
```
> This script automatically detects your architecture, downloads the latest Go-built ELF binary release, initializes the environment, and sets up `vpshelper.service` via systemd.

## Building from Source

```bash
cd goapp
go build -o ../bin/vpshelper ./cmd/server
```

## Security & Text Integrity

Enable the local pre-commit hook to prevent Chinese garbled text errors:

**Linux/macOS**:
```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit scripts/check_text_integrity.sh
```

**Windows (PowerShell)**:
```powershell
git config core.hooksPath .githooks
sh ./scripts/check_text_integrity.sh --all
```

## Environment Variables & Overrides

| Variable | Description | Default |
|-------------|-------------|---------|
| `VPSHELPER_LISTEN` | Bind address/port for the web server | `:15018` |
| `VPSHELPER_DATA_DIR` | Absolute path to the runtime storage layer | `./userdata` |
| `TZ` / `VPSHELPER_TZ` | Timezone setting context | `Asia/Shanghai` |

- **Default Address**: `http://127.0.0.1:15018`
- **Database**: `${VPSHELPER_DATA_DIR}/VpsHelper.db`
