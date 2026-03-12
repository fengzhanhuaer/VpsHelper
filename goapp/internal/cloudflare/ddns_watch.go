package cloudflare

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tunnel"
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

// TriggerProbeDDNS immediately attempts to update the Cloudflare DNS A/AAAA
// record for the probe_ddns_domain setting. It clears the cached IP key first
// so the update always runs even if the IP hasn't changed (e.g. domain was
// just configured). Returns an error string for display in the UI, or "" on success.
func TriggerProbeDDNS(dbConn *sql.DB) string {
	keys := []string{"cf_api_token", "cf_account_id", "cf_zone_id", "cf_zone_domain", "probe_ddns_domain"}
	settings, err := store.GetSettings(dbConn, keys)
	if err != nil {
		return "读取设置失败: " + err.Error()
	}

	cfToken := strings.TrimSpace(settings["cf_api_token"])
	if cfToken == "" {
		return "Cloudflare API Token 未配置，请先在 Cloudflare 设置中填写。"
	}

	probeDDNSDomain := strings.ToLower(strings.TrimSpace(settings["probe_ddns_domain"]))
	if probeDDNSDomain == "" {
		return "DDNS 域名为空，跳过更新。"
	}

	accountID := strings.TrimSpace(settings["cf_account_id"])

	tempClient := NewAPIClient(cfToken, accountID, "")
	ddnsZoneID := ""

	// 优先尝试从 DDNS 域名本身获取对应的 Zone ID
	if id, err := tempClient.LookupZoneID(probeDDNSDomain); err == nil && id != "" {
		ddnsZoneID = id
	}

	if ddnsZoneID == "" {
		return "无法确定 DDNS 域名对应的 Cloudflare Zone ID，请检查 API Token 权限或域名归属。"
	}

	client := NewAPIClient(cfToken, accountID, ddnsZoneID)

	ips := GetPublicIPs()
	if ips.IPv4 == "" && ips.IPv6 == "" {
		return "无法获取本机公网 IP，DDNS 更新中止。"
	}

	// Reset the cached key so the background watcher also re-syncs on next tick
	_ = store.SetLocalSetting("probe_ddns_last_ip", "")

	if _, err := client.SyncDDNSRecord(probeDDNSDomain, ips); err != nil {
		log.Printf("[ddns] TriggerProbeDDNS failed: %v", err)
		return "DDNS 更新失败: " + err.Error()
	}

	currentIPKey := ips.IPv4 + "|" + ips.IPv6
	_ = store.SetLocalSetting("probe_ddns_last_ip", currentIPKey)
	log.Printf("[ddns] TriggerProbeDDNS: updated %s -> v4=%s v6=%s", probeDDNSDomain, ips.IPv4, ips.IPv6)
	return ""
}

// TriggerNodeDDNS forces an immediate update of all online nodes' DDNS records
func TriggerNodeDDNS(dbConn *sql.DB) string {
	keys := []string{"cf_api_token", "cf_account_id", "probe_node_ddns_domain", "probe_node_ddns_prefix"}
	settings, err := store.GetSettings(dbConn, keys)
	if err != nil {
		return "读取设置失败: " + err.Error()
	}

	cfToken := strings.TrimSpace(settings["cf_api_token"])
	if cfToken == "" {
		return "Cloudflare API Token 未配置"
	}

	nodeDDNSDomain := strings.ToLower(strings.TrimSpace(settings["probe_node_ddns_domain"]))
	if nodeDDNSDomain == "" {
		return "未配置节点 DDNS 主域名"
	}

	nodeDDNSPrefix := strings.ToLower(strings.TrimSpace(settings["probe_node_ddns_prefix"]))
	if nodeDDNSPrefix == "" {
		nodeDDNSPrefix = "api.gateway.ai."
	}
	if !strings.HasSuffix(nodeDDNSPrefix, ".") {
		nodeDDNSPrefix += "."
	}

	accountID := strings.TrimSpace(settings["cf_account_id"])
	tempClient := NewAPIClient(cfToken, accountID, "")

	ddnsZoneID := ""
	if id, err := tempClient.LookupZoneID(nodeDDNSDomain); err == nil && id != "" {
		ddnsZoneID = id
	}

	if ddnsZoneID == "" {
		return "无法确定域名对应的 Cloudflare Zone ID"
	}

	client := NewAPIClient(cfToken, accountID, ddnsZoneID)

	nodes, err := store.ListProbeNodes(dbConn)
	if err != nil {
		return "获取节点列表失败"
	}

	count := 0
	for _, n := range nodes {
		if !n.Online || len(n.IPInfos) == 0 {
			continue
		}

		var ips PublicIPs
		for _, ipInfo := range n.IPInfos {
			if strings.Contains(ipInfo.Raw, ":") {
				if ips.IPv6 == "" {
					ips.IPv6 = ipInfo.Raw
				}
			} else {
				if ips.IPv4 == "" {
					ips.IPv4 = ipInfo.Raw
				}
			}
		}

		if ips.IPv4 == "" && ips.IPv6 == "" {
			continue
		}

		// clear last ip cache to force update
		cacheKey := fmt.Sprintf("node_ddns_last_ip_%d", n.ID)
		_ = store.SetLocalSetting(cacheKey, "")

		encodedID := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(n.ID, 10)))
		subDomain := strings.ToLower(fmt.Sprintf("%s%s.%s", nodeDDNSPrefix, encodedID, nodeDDNSDomain))

		// Push DDNS unconditionally if triggering manually or if local cache is empty
		if _, err := client.SyncDDNSRecord(subDomain, ips); err != nil {
			log.Printf("[ddns] TriggerNodeDDNS node %d failed: %v", n.ID, err)
		} else {
			_ = store.SetLocalSetting(cacheKey, ips.IPv4+"|"+ips.IPv6)
			count++

			// Check if we need to request a TLS cert for this new/updated domain
			if n.TLSCertPem == "" || n.Domain != subDomain {
				go tunnel.RequestNodeCertificate(dbConn, n.ID, subDomain)
			}
		}
	}

	log.Printf("[ddns] TriggerNodeDDNS updated %d nodes", count)
	return ""
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
		"probe_ddns_domain", "probe_node_ddns_domain", "probe_node_ddns_prefix",
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

	// Actively ensure Account ID is correct, as old ones may become stale
	if id, err := client.FetchAccountID(); err == nil && id != "" {
		accountID = id
		client.AccountID = accountID
	}

	// ── 1. ZeroTrust WhiteList ─────────────────────────────
	if allowIPs != "" && accountID != "" {
		currentAllowKey := domainIPKey(splitLines(allowIPs))
		if currentAllowKey != lastAllowKey {
			// Pass "" to force it to lookup the correct policy by name instead of trusting a potentially stale policyID cache
			newPolicyID, err := client.SyncReusablePolicy("", splitLines(allowIPs))
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
		// Actively resolve zone ID unconditionally to prevent stale cache issues
		domain := zoneDomain
		if domain == "" {
			log.Printf("[ddns-watch] no zone domain configured, skipping BlockList sync")
		} else {
			if id, err := client.LookupZoneID(domain); err == nil && id != "" {
				zoneID = id
				_ = store.SetSetting(dbConn, "cf_zone_id", zoneID)
				client = NewAPIClient(cfToken, accountID, zoneID)
			} else {
				// If Lookup failed, at least clear the cached zoneID to avoid performing operations on the wrong zone
				zoneID = ""
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
	probeDDNSDomain := strings.ToLower(strings.TrimSpace(settings["probe_ddns_domain"]))
	if probeDDNSDomain != "" && cfToken != "" {
		ddnsZoneID := ""
		tempClient := NewAPIClient(cfToken, accountID, "")

		// 取 DDNS 域名自己的 Zone ID
		if id, err := tempClient.LookupZoneID(probeDDNSDomain); err == nil && id != "" {
			ddnsZoneID = id
		}

		if ddnsZoneID != "" {
			ddnsClient := NewAPIClient(cfToken, accountID, ddnsZoneID)
			ips := GetPublicIPs()
			currentIPKey := ips.IPv4 + "|" + ips.IPv6
			lastIPKey := store.GetLocalSetting("probe_ddns_last_ip")

			if currentIPKey != "|" {
				// Cloudflare 反查: 始终进行 SyncDDNSRecord (其内部包含了查询现存记录的逻辑)。
				// 如果 Cloudflare 上的记录不存在或与当前不符，将自动增加或更新。
				updated, err := ddnsClient.SyncDDNSRecord(probeDDNSDomain, ips)
				if err != nil {
					log.Printf("[ddns-watch] probe DDNS sync failed: %v", err)
				} else if updated || currentIPKey != lastIPKey {
					// 仅当地 IP 变化，或 Cloudflare 侧记录发生变动时刷新并打印日志
					_ = store.SetLocalSetting("probe_ddns_last_ip", currentIPKey)
					log.Printf("[ddns-watch] probe DDNS updated for %s: v4=%s, v6=%s", probeDDNSDomain, ips.IPv4, ips.IPv6)
				}
			}
		}
	}

	// ── 4. Nodes Auto DDNS (prefix{ID}.domain) ────────────
	nodeDDNSDomain := strings.ToLower(strings.TrimSpace(settings["probe_node_ddns_domain"]))
	nodeDDNSPrefix := strings.ToLower(strings.TrimSpace(settings["probe_node_ddns_prefix"]))
	if nodeDDNSPrefix == "" {
		nodeDDNSPrefix = "api.gateway.ai."
	}
	if !strings.HasSuffix(nodeDDNSPrefix, ".") {
		nodeDDNSPrefix += "."
	}

	if nodeDDNSDomain != "" && cfToken != "" {
		ddnsZoneID := ""
		tempClient := NewAPIClient(cfToken, accountID, "")

		if id, err := tempClient.LookupZoneID(nodeDDNSDomain); err == nil && id != "" {
			ddnsZoneID = id
		}

		if ddnsZoneID != "" {
			ddnsClient := NewAPIClient(cfToken, accountID, ddnsZoneID)

			nodes, err := store.ListProbeNodes(dbConn)
			if err == nil {
				for _, n := range nodes {
					if !n.Online || len(n.IPInfos) == 0 {
						continue
					}

					var ips PublicIPs
					for _, ipInfo := range n.IPInfos {
						if strings.Contains(ipInfo.Raw, ":") {
							if ips.IPv6 == "" {
								ips.IPv6 = ipInfo.Raw
							}
						} else {
							if ips.IPv4 == "" {
								ips.IPv4 = ipInfo.Raw
							}
						}
					}

					if ips.IPv4 == "" && ips.IPv6 == "" {
						continue
					}

					currentIPKey := ips.IPv4 + "|" + ips.IPv6
					cacheKey := fmt.Sprintf("node_ddns_last_ip_%d", n.ID)
					lastIPKey := store.GetLocalSetting(cacheKey)

					encodedID := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(n.ID, 10)))
					subDomain := strings.ToLower(fmt.Sprintf("%s%s.%s", nodeDDNSPrefix, encodedID, nodeDDNSDomain))

					needsCertRequest := false

					// Request TLS Certificate if missing, domain changed, or expiring soon
					if n.TLSCertPem == "" || n.Domain != subDomain {
						needsCertRequest = true
					} else if n.TLSCertExpired != "" {
						if t, err := time.Parse("2006-01-02 15:04:05", n.TLSCertExpired); err == nil {
							if time.Until(t) < 30*24*time.Hour { // Renew if < 30 days
								needsCertRequest = true
							}
						}
					}

					// Cloudflare 反查: 始终进行 SyncDDNSRecord 以确保节点记录不会丢失。
					if currentIPKey != "|" {
						updated, err := ddnsClient.SyncDDNSRecord(subDomain, ips)
						if err != nil {
							log.Printf("[ddns-watch] node %d DDNS sync failed: %v", n.ID, err)
						} else if updated || currentIPKey != lastIPKey || lastIPKey == "" {
							_ = store.SetLocalSetting(cacheKey, currentIPKey)
							log.Printf("[ddns-watch] node %d DDNS updated for %s: v4=%s, v6=%s", n.ID, subDomain, ips.IPv4, ips.IPv6)
						}
					}

					if needsCertRequest {
						go tunnel.RequestNodeCertificate(dbConn, n.ID, subDomain)
					}
				}
			}
		}
	}
}
