package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"vpshelper-go/internal/store"
)

type DomainRule struct {
	Domain   string `json:"domain"`
	Suffix   string `json:"suffix"` // newly added for "/56", etc.
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

var watchTicker *time.Ticker

// helper to resolve domain to IPs and append matched CIDR suffix
func ResolveIPWithCIDR(domain, suffix string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	var results []string
	hasV4 := false
	hasV6 := false

	for _, ip := range ips {
		if ip.To4() != nil && !hasV4 {
			hasV4 = true
			if suffix != "" {
				results = append(results, ip.String()+"/32")
			} else {
				results = append(results, ip.String())
			}
		} else if ip.To4() == nil && !hasV6 {
			hasV6 = true
			if suffix != "" {
				results = append(results, ip.String()+suffix)
			} else {
				results = append(results, ip.String())
			}
		}
	}

	return results, nil
}

func StartDomainWatch(ctx context.Context, dbConn *sql.DB) {
	watchTicker = time.NewTicker(5 * time.Minute)

	// Run once on startup
	go runDomainWatchTick(ctx, dbConn)

	go func() {
		for {
			select {
			case <-ctx.Done():
				watchTicker.Stop()
				return
			case <-watchTicker.C:
				runDomainWatchTick(ctx, dbConn)
			}
		}
	}()
}

func runDomainWatchTick(ctx context.Context, dbConn *sql.DB) {
	settings, err := store.GetSettings(dbConn, []string{"fw_domain_rules"})
	if err != nil {
		return
	}

	rulesJSON := settings["fw_domain_rules"]
	if rulesJSON == "" {
		return
	}

	var rules []DomainRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		log.Printf("[firewall-watch] Parse fw_domain_rules failed: %v", err)
		return
	}

	fwType := DetectType()
	if fwType == "未知" || fwType == "" {
		return
	}

	for i := range rules {
		rule := &rules[i]
		currentIPsSlice, err := ResolveIPWithCIDR(rule.Domain, rule.Suffix)
		if err != nil || len(currentIPsSlice) == 0 {
			// Cannot resolve, keep old
			continue
		}

		// Sort or just serialize to compare
		currentIPsStr := ""
		if len(currentIPsSlice) > 0 {
			b, _ := json.Marshal(currentIPsSlice)
			currentIPsStr = string(b)
		}

		cacheKey := fmt.Sprintf("fw_cache_%s_%s_%d_%s", rule.Domain, rule.Suffix, rule.Port, rule.Protocol)
		lastIPsStr := store.GetLocalSetting(cacheKey)

		if currentIPsStr != lastIPsStr {
			// IPs changed
			if lastIPsStr != "" {
				var oldIPs []string
				_ = json.Unmarshal([]byte(lastIPsStr), &oldIPs)
				for _, ip := range oldIPs {
					DeletePort(fwType, rule.Port, rule.Protocol, ip)
				}
			}
			for _, ip := range currentIPsSlice {
				OpenPort(fwType, rule.Port, rule.Protocol, ip)
			}
			_ = store.SetLocalSetting(cacheKey, currentIPsStr)
			log.Printf("[firewall-watch] Domain %s updated IP to %s for port %d/%s", rule.Domain, currentIPsStr, rule.Port, rule.Protocol)
		}
	}
}

// AddDomainRule is a helper to securely append a new domain to the list
func AddDomainRule(dbConn *sql.DB, domain string, suffix string, port int, protocol string, initialIPsSlice []string) error {
	settings, _ := store.GetSettings(dbConn, []string{"fw_domain_rules"})
	var rules []DomainRule
	if settings["fw_domain_rules"] != "" {
		_ = json.Unmarshal([]byte(settings["fw_domain_rules"]), &rules)
	}

	initialStr := ""
	if len(initialIPsSlice) > 0 {
		b, _ := json.Marshal(initialIPsSlice)
		initialStr = string(b)
	}

	cacheKey := fmt.Sprintf("fw_cache_%s_%s_%d_%s", domain, suffix, port, protocol)
	_ = store.SetLocalSetting(cacheKey, initialStr)

	// Avoid duplicates
	for _, r := range rules {
		if r.Domain == domain && r.Suffix == suffix && r.Port == port && r.Protocol == protocol {
			return nil
		}
	}

	rules = append(rules, DomainRule{
		Domain:   domain,
		Suffix:   suffix,
		Port:     port,
		Protocol: protocol,
	})
	newJSON, _ := json.Marshal(rules)
	return store.SetSetting(dbConn, "fw_domain_rules", string(newJSON))
}
