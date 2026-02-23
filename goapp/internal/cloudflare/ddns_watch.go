package cloudflare

import (
	"context"
	"database/sql"
	"log"
	"net"
	"strings"
	"time"

	"vpshelper-go/internal/store"
)

// StartDDNSWatch launches a background goroutine that periodically resolves
// every domain listed in cf_allow_ips (ZeroTrust WhiteList) and cf_block_ips
// (Firewall BlockList). When any IP changes it automatically pushes a fresh
// sync to the corresponding Cloudflare service.
//
// Interval: 5 minutes.
func StartDDNSWatch(ctx context.Context, dbConn *sql.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		// Run once at startup so changes are picked up quickly after restart.
		runDDNSWatchTick(ctx, dbConn)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runDDNSWatchTick(ctx, dbConn)
			}
		}
	}()
}

// domainIPKey computes a stable string representing the current resolved IPs
// of all hostnames in a list of IP/CIDR/domain entries.
// Pure IPs are skipped (stable); only domains are resolved and included.
func domainIPKey(lines []string) string {
	var parts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip ASNs (AS12345)
		if strings.HasPrefix(strings.ToUpper(line), "AS") {
			continue
		}
		// Extract host (strip optional /prefix)
		host := line
		if idx := strings.Index(line, "/"); idx != -1 {
			host = line[:idx]
		}
		host = strings.TrimSpace(host)
		// Skip plain IPs
		if net.ParseIP(host) != nil {
			continue
		}
		// Domain — resolve it
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			parts = append(parts, host+"=?")
		} else {
			parts = append(parts, host+"="+strings.Join(addrs, ","))
		}
	}
	return strings.Join(parts, "|")
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func runDDNSWatchTick(ctx context.Context, dbConn *sql.DB) {
	keys := []string{
		"cf_api_token", "cf_account_id", "cf_zone_id", "cf_zone_domain",
		"cf_allow_ips", "cf_policy_id",
		"cf_block_ips", "cf_block_uris",
		"probe_ddns_domain",
	}
	settings, err := store.GetSettings(dbConn, keys)
	if err != nil {
		return
	}

	cfToken := strings.TrimSpace(settings["cf_api_token"])
	if cfToken == "" {
		return // not configured
	}

	accountID := strings.TrimSpace(settings["cf_account_id"])
	zoneID := strings.TrimSpace(settings["cf_zone_id"])
	zoneDomain := strings.TrimSpace(settings["cf_zone_domain"])
	policyID := strings.TrimSpace(settings["cf_policy_id"])

	allowIPs := strings.TrimSpace(settings["cf_allow_ips"])
	blockIPs := strings.TrimSpace(settings["cf_block_ips"])
	blockURIs := strings.TrimSpace(settings["cf_block_uris"])

	lastAllowKey := store.GetLocalSetting("cf_ddns_allow_key")
	lastBlockKey := store.GetLocalSetting("cf_ddns_block_key")

	client := NewAPIClient(cfToken, accountID, zoneID)

	// ── 1. ZeroTrust WhiteList ─────────────────────────────
	if allowIPs != "" && accountID != "" {
		currentAllowKey := domainIPKey(splitLines(allowIPs))
		if currentAllowKey != lastAllowKey {
			newPolicyID, err := client.SyncReusablePolicy(policyID, splitLines(allowIPs))
			if err != nil {
				log.Printf("[ddns-watch] SyncReusablePolicy failed: %v", err)
			} else {
				if policyID == "" && newPolicyID != "" {
					_ = store.SetSetting(dbConn, "cf_policy_id", newPolicyID)
				}
				_ = store.SetLocalSetting("cf_ddns_allow_key", currentAllowKey)
				log.Printf("[ddns-watch] whitelist IP change detected, pushed update")
			}
		}
	}

	// ── 2. Firewall BlockList ──────────────────────────────
	if blockIPs != "" && blockURIs != "" {
		// Resolve zone ID if missing
		if zoneID == "" {
			domain := zoneDomain
			if domain == "" {
				// Can't auto-detect domain from background goroutine; skip
				log.Printf("[ddns-watch] zone ID missing and no zone domain configured, skipping BlockList sync")
			} else {
				if id, err := client.LookupZoneID(domain); err == nil && id != "" {
					zoneID = id
					_ = store.SetSetting(dbConn, "cf_zone_id", zoneID)
					client = NewAPIClient(cfToken, accountID, zoneID)
				}
			}
		}

		if zoneID != "" {
			currentBlockKey := domainIPKey(splitLines(blockIPs))
			if currentBlockKey != lastBlockKey {
				err := client.SyncBlockList(splitLines(blockURIs), splitLines(blockIPs))
				if err != nil {
					log.Printf("[ddns-watch] SyncBlockList failed: %v", err)
				} else {
					_ = store.SetLocalSetting("cf_ddns_block_key", currentBlockKey)
					log.Printf("[ddns-watch] blocklist IP change detected, pushed update")
				}
			}
		}
	}

	// ── 3. Probe DDNS (Auto Update A/AAAA) ─────────────────
	probeDDNSDomain := strings.TrimSpace(settings["probe_ddns_domain"])
	if probeDDNSDomain != "" && cfToken != "" {
		if zoneID == "" && zoneDomain != "" {
			if id, err := client.LookupZoneID(zoneDomain); err == nil && id != "" {
				zoneID = id
				_ = store.SetSetting(dbConn, "cf_zone_id", zoneID)
				client = NewAPIClient(cfToken, accountID, zoneID)
			}
		}

		if zoneID != "" {
			ips := GetPublicIPs()
			currentIPKey := ips.IPv4 + "|" + ips.IPv6
			lastIPKey := store.GetLocalSetting("probe_ddns_last_ip")

			if currentIPKey != "|" && currentIPKey != lastIPKey {
				err := client.SyncDDNSRecord(probeDDNSDomain, ips)
				if err != nil {
					log.Printf("[ddns-watch] probe DDNS sync failed: %v", err)
				} else {
					_ = store.SetLocalSetting("probe_ddns_last_ip", currentIPKey)
					log.Printf("[ddns-watch] probe DDNS updated for %s: v4=%s, v6=%s", probeDDNSDomain, ips.IPv4, ips.IPv6)
				}
			}
		}
	}
}
