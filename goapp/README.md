# VpsHelper Go (Gin)

This folder contains the Go migration skeleton.

## Run

```bash
go run ./cmd/server
```

## Update UI

After login, visit `/system/update` to check/pull updates.

## Configuration

- VPSHELPER_LISTEN: server listen address (default :15018)
- VPSHELPER_DATA_DIR: userdata directory (default ../userdata)
- VPSHELPER_TEMPLATES_DIR: optional template directory override (default: embedded templates)
- VPSHELPER_SESSION_KEY: cookie session key (default change-this-key)
