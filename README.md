# VpsHelper

VpsHelper is now **Go-only** (Gin + SQLite). All legacy Python code has been removed.

- Default address: `http://127.0.0.1:15018`
- Local database: `./userdata/VpsHelper.db`
- Cloudflare D1 default name: `VpsHelper.db`

## Run locally

### Windows

```powershell
cd goapp
go run ./cmd/server
```

or run from repo root:

```powershell
.\VpsHelper.bat
```

### Linux/macOS

```bash
cd goapp
go run ./cmd/server
```

or run from repo root:

```bash
chmod +x VpsHelper.sh
./VpsHelper.sh
```

## Install as Linux service

Recommended:

```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install-go.sh | sudo bash
```

Compatibility entrypoint (`install.sh`) now delegates to `install-go.sh`.

## Build

```bash
cd goapp
go build -o ./bin/vpshelper ./cmd/server
```

## Project structure

- `goapp/`: Go source code
- `goapp/templates/`: Web templates (embedded at build time)
- `install-go.sh`: one-click Linux service installer
- `install.sh`: compatibility wrapper to Go installer
- `VpsHelper.sh`: local startup script (Go)
- `VpsHelper.bat`: local startup script (Go)
- `userdata/`: runtime data directory

## Notes

- Default timezone is `Asia/Shanghai` (override with `TZ` or `VPSHELPER_TZ`).
- Default listen address can be overridden by `VPSHELPER_LISTEN`.
- Runtime data dir can be overridden by `VPSHELPER_DATA_DIR`.
