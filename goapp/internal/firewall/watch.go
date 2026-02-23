package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"time"

	"vpshelper-go/internal/store"
)

type DomainRule struct {
	Domain   string `json:"domain"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	LastIP   string `json:"last_ip"`
}

var watchTicker *time.Ticker

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

	changed := false
	for i := range rules {
		rule := &rules[i]
		ips, err := net.LookupIP(rule.Domain)
		if err != nil || len(ips) == 0 {
			// Cannot resolve, keep old
			continue
		}

		// take first IPv4 (or let fallback handle it, ufw supports v6 too)
		var currentIP string
		for _, ip := range ips {
			if ip.To4() != nil {
				currentIP = ip.String()
				break
			}
		}
		if currentIP == "" {
			currentIP = ips[0].String()
		}

		if currentIP != rule.LastIP {
			// IP changed
			if rule.LastIP != "" {
				DeletePort(fwType, rule.Port, rule.Protocol, rule.LastIP)
			}
			OpenPort(fwType, rule.Port, rule.Protocol, currentIP)
			rule.LastIP = currentIP
			changed = true
			log.Printf("[firewall-watch] Domain %s updated IP to %s for port %d/%s", rule.Domain, currentIP, rule.Port, rule.Protocol)
		}
	}

	if changed {
		newJSON, _ := json.Marshal(rules)
		_ = store.SetSetting(dbConn, "fw_domain_rules", string(newJSON))
	}
}

// AddDomainRule is a helper to securely append a new domain to the list
func AddDomainRule(dbConn *sql.DB, domain string, port int, protocol string, initialIP string) error {
	settings, _ := store.GetSettings(dbConn, []string{"fw_domain_rules"})
	var rules []DomainRule
	if settings["fw_domain_rules"] != "" {
		_ = json.Unmarshal([]byte(settings["fw_domain_rules"]), &rules)
	}

	// Avoid duplicates
	for i, r := range rules {
		if r.Domain == domain && r.Port == port && r.Protocol == protocol {
			rules[i].LastIP = initialIP
			newJSON, _ := json.Marshal(rules)
			return store.SetSetting(dbConn, "fw_domain_rules", string(newJSON))
		}
	}

	rules = append(rules, DomainRule{
		Domain:   domain,
		Port:     port,
		Protocol: protocol,
		LastIP:   initialIP,
	})
	newJSON, _ := json.Marshal(rules)
	return store.SetSetting(dbConn, "fw_domain_rules", string(newJSON))
}
