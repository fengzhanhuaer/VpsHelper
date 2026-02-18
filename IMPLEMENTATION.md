# VpsHelper Implementation

## Status

The project is now **Go-only**.

- Web framework: Gin
- DB: SQLite (`userdata/VpsHelper.db`)
- Cloud backup: Cloudflare D1 (`VpsHelper.db`)
- Default port: `15018`

## Main modules

- Auth: register/login/change-password
- TG: login, accounts, dialogs, auto send, auto reply, sign tasks
- Server ops: status, shell, firewall, SSH settings
- Data sync: local SQLite <-> Cloudflare D1 backup/pull, daily auto backup
- Update: GitHub release update + restart

## Runtime layout

- `goapp/cmd/server/main.go`: server entrypoint
- `goapp/internal/`: business modules
- `goapp/templates/`: HTML templates (embedded)
- `userdata/`: local runtime data

## Configuration

- `VPSHELPER_LISTEN`: listen address, default `:15018`
- `VPSHELPER_DATA_DIR`: data directory
- `VPSHELPER_SESSION_KEY`: session signing key
- `TZ`: timezone, default `Asia/Shanghai`

## Deploy

Use `install-go.sh` for Linux systemd deployment.
