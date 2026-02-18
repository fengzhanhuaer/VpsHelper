# Requirements

## Target

VpsHelper is implemented and maintained in Go only.

- Backend: Go (Gin)
- Storage: SQLite (`userdata/VpsHelper.db`)
- Optional cloud DB: Cloudflare D1 (`VpsHelper.db`)

## Functional scope

- User auth and session management
- TG account login and task management
- Auto send / auto reply / sign tasks
- Server status, shell tools, firewall, SSH settings
- Local/Cloud DB sync and scheduled backup
- Program update and restart

## Non-functional requirements

- Single-binary deployment supported
- Linux service deployment with systemd (`install-go.sh`)
- Backward-compatible local DB schema where possible
- Configurable listen addr, data dir, timezone, session key via environment variables
