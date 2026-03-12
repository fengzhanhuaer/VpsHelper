package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type APIClient struct {
	Token     string
	AccountID string
	ZoneID    string
}

func NewAPIClient(token, accountID, zoneID string) *APIClient {
	return &APIClient{
		Token:     token,
		AccountID: accountID,
		ZoneID:    zoneID,
	}
}

func (c *APIClient) doRequest(method, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// FetchAccountID gets the first available account ID from Cloudflare
func (c *APIClient) FetchAccountID() (string, error) {
	respBytes, err := c.doRequest("GET", "https://api.cloudflare.com/client/v4/accounts?page=1&per_page=1", nil)
	if err != nil {
		return "", err
	}

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", fmt.Errorf("failed to parse accounts: %w", err)
	}
	if !result.Success || len(result.Result) == 0 || result.Result[0].ID == "" {
		return "", fmt.Errorf("no account found or API unsuccessful")
	}

	return result.Result[0].ID, nil
}

// LookupZoneID finds the Zone ID for a given domain name.
// Tries progressively shorter suffixes (sub.example.com → example.com)
// since Cloudflare zones are registered at the root domain level.
func (c *APIClient) LookupZoneID(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", candidate)
		respBytes, err := c.doRequest("GET", url, nil)
		if err != nil {
			continue
		}
		var result struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := json.Unmarshal(respBytes, &result); err != nil {
			continue
		}
		if result.Success && len(result.Result) > 0 {
			return result.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("no zone found for domain: %s", domain)
}

func expandIPsAndDomains(items []string) []string {
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		upper := strings.ToUpper(item)
		if strings.HasPrefix(upper, "AS") {
			result = append(result, item)
			continue
		}

		// Check if it's purely numeric
		if isNumeric(item) {
			result = append(result, item)
			continue
		}

		// Split CIDR if present
		host := item
		cidr := ""
		if idx := strings.Index(item, "/"); idx != -1 {
			host = item[:idx]
			cidr = item[idx:]
		}

		// Try parsing as IP first
		if net.ParseIP(host) != nil {
			result = append(result, item)
			continue
		}

		// Not an IP, try resolving as domain
		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			for _, resolvedIP := range ips {
				if v4 := resolvedIP.To4(); v4 != nil {
					// IPv4 address → always use /32 (host route)
					result = append(result, v4.String()+"/32")
				} else {
					// IPv6 address → use user-specified CIDR (e.g. /56) or /128
					ipv6CIDR := cidr
					if ipv6CIDR == "" {
						ipv6CIDR = "/128"
					}
					result = append(result, resolvedIP.String()+ipv6CIDR)
				}
			}
		} else {
			// Resolution failed, keep original so API errs or it's handled downstream
			result = append(result, item)
		}
	}
	return result
}

func buildCFExpression(uris []string, ips []string) string {
	var uriExprs []string
	for _, uri := range uris {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		if strings.HasPrefix(uri, "http") || strings.Contains(uri, "://") {
			uriExprs = append(uriExprs, fmt.Sprintf(`http.request.full_uri eq "%s"`, uri))
		} else {
			uriExprs = append(uriExprs, fmt.Sprintf(`http.request.uri.path eq "%s"`, uri))
		}
	}

	if len(uriExprs) == 0 {
		return ""
	}
	uriCondition := "(" + strings.Join(uriExprs, " or ") + ")"

	var ipList []string
	var asnList []string

	ips = expandIPsAndDomains(ips)

	for _, item := range ips {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		upper := strings.ToUpper(item)
		if strings.HasPrefix(upper, "AS") {
			asnList = append(asnList, upper[2:])
		} else if isNumeric(item) {
			asnList = append(asnList, item)
		} else {
			ipList = append(ipList, item)
		}
	}

	var allowedExprs []string
	if len(ipList) > 0 {
		allowedExprs = append(allowedExprs, fmt.Sprintf(`ip.src in {%s}`, strings.Join(ipList, " ")))
	}
	if len(asnList) > 0 {
		allowedExprs = append(allowedExprs, fmt.Sprintf(`ip.geoip.asnum in {%s}`, strings.Join(asnList, " ")))
	}

	if len(allowedExprs) > 0 {
		return fmt.Sprintf(`(%s and not (%s))`, uriCondition, strings.Join(allowedExprs, " or "))
	}
	return uriCondition
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (c *APIClient) SyncBlockList(uris []string, ips []string) error {
	if c.ZoneID == "" {
		return fmt.Errorf("Zone ID is required for Firewall BlockList")
	}

	expr := buildCFExpression(uris, ips)
	if expr == "" {
		return fmt.Errorf("URI/URL list is empty. Cannot build firewall rule")
	}

	// 1. Fetch rulesets
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets", c.ZoneID)
	respBytes, err := c.doRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to fetch rulesets: %v", err)
	}

	type ruleset struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
		Kind  string `json:"kind"`
	}
	var fetchResult struct {
		Success bool      `json:"success"`
		Result  []ruleset `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &fetchResult); err != nil {
		return fmt.Errorf("failed to parse access rules: %v", err)
	}

	var rulesetID string
	for _, rs := range fetchResult.Result {
		if rs.Phase == "http_request_firewall_custom" && rs.Kind == "zone" {
			rulesetID = rs.ID
			break
		}
	}

	rulePayload := map[string]interface{}{
		"description": "BlockList",
		"expression":  expr,
		"action":      "block",
	}

	if rulesetID == "" {
		createPayload := map[string]interface{}{
			"name":        "default",
			"kind":        "zone",
			"description": "Zone level custom rules",
			"phase":       "http_request_firewall_custom",
			"rules":       []interface{}{rulePayload},
		}
		bodyBytes, _ := json.Marshal(createPayload)
		postURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets", c.ZoneID)
		_, err := c.doRequest("POST", postURL, bodyBytes)
		if err != nil {
			return fmt.Errorf("failed to create ruleset: %v", err)
		}
		return nil
	}

	// Fetch rules to find BlockList
	url = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s", c.ZoneID, rulesetID)
	respBytes, err = c.doRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to fetch ruleset rules: %v", err)
	}

	var rulesFetchResult struct {
		Success bool `json:"success"`
		Result  struct {
			Rules []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
			} `json:"rules"`
		} `json:"result"`
	}
	_ = json.Unmarshal(respBytes, &rulesFetchResult)

	var ruleID string
	for _, r := range rulesFetchResult.Result.Rules {
		if r.Description == "BlockList" {
			ruleID = r.ID
			break
		}
	}

	if ruleID == "" {
		bodyBytes, _ := json.Marshal(rulePayload)
		postURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s/rules", c.ZoneID, rulesetID)
		_, err := c.doRequest("POST", postURL, bodyBytes)
		if err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}
	} else {
		bodyBytes, _ := json.Marshal(rulePayload)
		patchURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s/rules/%s", c.ZoneID, rulesetID, ruleID)
		_, err := c.doRequest("PATCH", patchURL, bodyBytes)
		if err != nil {
			return fmt.Errorf("failed to update rule: %v", err)
		}
	}

	return nil
}

// SyncReusablePolicy updates a ZeroTrust Reusable Policy to include the allowed IPs
func (c *APIClient) SyncReusablePolicy(policyID string, ips []string) (string, error) {
	if c.AccountID == "" {
		return "", fmt.Errorf("Account ID is required for ZeroTrust Reusable Policy")
	}

	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/access/policies", c.AccountID)

	if policyID == "" {
		listResp, err := c.doRequest("GET", listURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed to list access groups: %v", err)
		}
		var listResult struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := json.Unmarshal(listResp, &listResult); err != nil {
			return "", fmt.Errorf("failed to parse access groups list: %v", err)
		}
		for _, p := range listResult.Result {
			if strings.EqualFold(p.Name, "WhiteList") {
				policyID = p.ID
				break
			}
		}

		if policyID == "" {
			newPolicy := map[string]interface{}{
				"name":     "WhiteList",
				"decision": "bypass",
				"include": []map[string]interface{}{
					{"ip": map[string]string{"ipv4": "127.0.0.1/32"}},
				},
			}
			bodyBytes, _ := json.Marshal(newPolicy)
			createResp, err := c.doRequest("POST", listURL, bodyBytes)
			if err != nil {
				return "", fmt.Errorf("failed to create WhiteList reusable policy: %v", err)
			}
			var createResult struct {
				Success bool `json:"success"`
				Result  struct {
					ID string `json:"id"`
				} `json:"result"`
			}
			if err := json.Unmarshal(createResp, &createResult); err != nil {
				return "", fmt.Errorf("failed to parse created reusable policy: %v", err)
			}
			if !createResult.Success {
				return "", fmt.Errorf("failed to create WhiteList reusable policy: %s", string(createResp))
			}
			policyID = createResult.Result.ID
		}
	}

	// 1. Fetch current policy
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/access/policies/%s", c.AccountID, policyID)
	respBytes, err := c.doRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch reusable policy: %v", err)
	}

	var fetchResult struct {
		Success bool                   `json:"success"`
		Result  map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &fetchResult); err != nil {
		return "", fmt.Errorf("failed to parse reusable policy: %v", err)
	}

	policy := fetchResult.Result

	// Create the "include" array with IPs
	var includes []map[string]interface{}
	// For ZeroTrust IP rules, if it doesn't have a CIDR suffix, we should append /32 for ipv4 or /128 for ipv6,
	// according to Cloudflare docs, but often just the IP is enough if Cloudflare auto-expands it,
	// However Cloudflare requires {"ip": {"ipv4": "198.51.100.4/32"}} for precise matching.
	// Actually, just passing {"ip": {"ipv4": "x.x.x.x/32"}} or {"ip": {"ipv6": "..."}} is safer.

	ips = expandIPsAndDomains(ips)

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		// Skip ASNs — not supported in ZeroTrust IP rules
		upper := strings.ToUpper(ip)
		if strings.HasPrefix(upper, "AS") || isNumeric(strings.SplitN(ip, "/", 2)[0]) {
			continue
		}

		// Split host from CIDR suffix
		host := ip
		cidr := ""
		if idx := strings.Index(ip, "/"); idx != -1 {
			host = ip[:idx]
			cidr = ip[idx:]
		}

		// Validate the host portion
		parsed := net.ParseIP(host)
		if parsed == nil {
			continue // skip invalid entries
		}

		// Convert IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4
		if v4 := parsed.To4(); v4 != nil {
			host = v4.String()
			parsed = v4
		}

		key := "ipv4"
		if strings.Contains(host, ":") {
			key = "ipv6"
		}

		// If CIDR is specified, validate and normalize the network address
		if cidr != "" {
			_, netw, err := net.ParseCIDR(host + cidr)
			if err != nil {
				// CIDR invalid — fall back to host-only
				cidr = ""
			} else {
				// Use the canonical network address (e.g. 2403:1::/56 not 2403:1::5/56)
				host = netw.IP.String()
				ones, _ := netw.Mask.Size()
				cidr = fmt.Sprintf("/%d", ones)
			}
		}

		if cidr == "" {
			if key == "ipv6" {
				cidr = "/128"
			} else {
				cidr = "/32"
			}
		}

		// Cloudflare Access Policy IP rule format: {"ip": {"ip": "x.x.x.x/32"}}
		// (NOT {"ip": {"ipv4": ...}} — both IPv4 and IPv6 use the single "ip" key)
		includes = append(includes, map[string]interface{}{
			"ip": map[string]string{
				"ip": host + cidr,
			},
		})
	}

	policy["include"] = includes
	policy["decision"] = "bypass" // Ensure decision is bypass

	bodyBytes, _ := json.Marshal(policy)
	putRespBytes, err := c.doRequest("PUT", url, bodyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to update reusable policy: %v", err)
	}

	var putResult struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(putRespBytes, &putResult); err != nil || !putResult.Success {
		return "", fmt.Errorf("failed to apply reusable policy changes: %s", string(putRespBytes))
	}

	return policyID, nil
}

// SyncDDNSRecord updates or creates A and AAAA records for a specific domain pointing to the host's current IPs.
func (c *APIClient) SyncDDNSRecord(domain string, ips PublicIPs) (bool, error) {
	if c.ZoneID == "" {
		return false, fmt.Errorf("Zone ID is required for DDNS")
	}
	if domain == "" {
		return false, fmt.Errorf("domain is required for DDNS")
	}

	// Fetch existing records for the domain
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s", c.ZoneID, domain)
	respBytes, err := c.doRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("fetch dns records for %s failed: %v", domain, err)
	}

	type dnsRecord struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	var fetchResult struct {
		Success bool        `json:"success"`
		Result  []dnsRecord `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &fetchResult); err != nil {
		return false, fmt.Errorf("parse dns records failed: %v", err)
	}

	existingV4 := ""
	existingV6 := ""
	idV4 := ""
	idV6 := ""

	for _, rec := range fetchResult.Result {
		if rec.Type == "A" {
			existingV4 = rec.Content
			idV4 = rec.ID
		} else if rec.Type == "AAAA" {
			existingV6 = rec.Content
			idV6 = rec.ID
		}
	}

	// Helper to create or patch
	upsertRecord := func(recType, content, id string) error {
		if content == "" {
			return nil
		}
		payload := map[string]interface{}{
			"type":    recType,
			"name":    domain,
			"content": content,
			"proxied": false, // Probe port connect should NOT be proxied if it's not on a standard HTTPS port natively supported by CF
		}
		bodyBytes, _ := json.Marshal(payload)

		if id == "" {
			// CREATE
			postURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", c.ZoneID)
			_, err := c.doRequest("POST", postURL, bodyBytes)
			if err != nil && strings.Contains(err.Error(), "81058") {
				return nil
			}
			return err
		}
		// UPDATE
		patchURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", c.ZoneID, id)
		_, err := c.doRequest("PUT", patchURL, bodyBytes)
		if err != nil && strings.Contains(err.Error(), "81058") {
			return nil
		}
		return err
	}

	var errV4, errV6 error
	updated := false
	if ips.IPv4 != "" && ips.IPv4 != existingV4 {
		errV4 = upsertRecord("A", ips.IPv4, idV4)
		if errV4 == nil {
			updated = true
		}
	}
	if ips.IPv6 != "" && ips.IPv6 != existingV6 {
		errV6 = upsertRecord("AAAA", ips.IPv6, idV6)
		if errV6 == nil {
			updated = true
		}
	}

	if errV4 != nil {
		return updated, fmt.Errorf("A record update failed: %v", errV4)
	}
	if errV6 != nil {
		return updated, fmt.Errorf("AAAA record update failed: %v", errV6)
	}
	return updated, nil
}
