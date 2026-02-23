package ssh

import (
	"context"
	"database/sql"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"vpshelper-go/internal/firewall"
	"vpshelper-go/internal/store"
)

var watchTicker *time.Ticker

func StartListenWatch(ctx context.Context, dbConn *sql.DB) {
	if watchTicker != nil {
		watchTicker.Stop()
	}
	watchTicker = time.NewTicker(5 * time.Minute)

	// Run once on startup
	go runListenWatchTick(ctx, dbConn)

	go func() {
		for {
			select {
			case <-ctx.Done():
				watchTicker.Stop()
				return
			case <-watchTicker.C:
				runListenWatchTick(ctx, dbConn)
			}
		}
	}()
}

func runListenWatchTick(ctx context.Context, dbConn *sql.DB) {
	dbSettings, err := store.GetSettings(dbConn, []string{"ssh_public_key", "ssh_listen_address"})
	if err != nil {
		return
	}
	listenAddrsRaw := dbSettings["ssh_listen_address"]
	pubKey := dbSettings["ssh_public_key"]
	lastAllowUsers := store.GetLocalSetting("ssh_last_allowusers")

	if listenAddrsRaw == "" {
		return
	}

	var addrs []string
	hasDomain := false
	parts := regexp.MustCompile(`[,\s]+`).Split(listenAddrsRaw, -1)
	for _, part := range parts {
		if part == "" {
			continue
		}
		base := part
		suffix := ""
		if idx := strings.LastIndex(part, "/"); idx != -1 {
			base = part[:idx]
			suffix = part[idx:]
		}

		if net.ParseIP(base) != nil {
			addrs = append(addrs, part)
		} else {
			hasDomain = true
			ips, err := firewall.ResolveIPWithCIDR(base, suffix)
			if err == nil && len(ips) > 0 {
				addrs = append(addrs, ips...)
			} else {
				// Keep raw if unresolvable so we don't accidentally drop it entirely if temporary DNS failure
				addrs = append(addrs, part)
			}
		}
	}

	if !hasDomain {
		return
	}

	expectedAllowUsers := ""
	if len(addrs) > 0 {
		var userPatterns []string
		for _, addr := range addrs {
			userPatterns = append(userPatterns, "*@"+addr)
		}
		expectedAllowUsers = "AllowUsers " + strings.Join(userPatterns, " ")
	}

	if lastAllowUsers != expectedAllowUsers {
		log.Printf("[ssh-watch] SSH domain IP changed (or newly set), updating sshd_config AllowUsers...")
		sysCfg := ReadSystemConfig()
		ok, msg := ApplySettings(ctx, sysCfg.Port, addrs, sysCfg.AllowPassword, sysCfg.AllowPubkey, pubKey)
		if !ok {
			log.Printf("[ssh-watch] Failed to apply SSH settings: %s", msg)
		} else {
			_ = store.SetLocalSetting("ssh_last_allowusers", expectedAllowUsers)
			log.Printf("[ssh-watch] SSH config updated successfully.")
		}
	}
}
