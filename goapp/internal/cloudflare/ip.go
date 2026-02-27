package cloudflare

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// PublicIPs holds the discovered public IPv4 and IPv6 addresses.
type PublicIPs struct {
	IPv4 string
	IPv6 string
}

// GetPublicIPs attempts to discover the host's public IPv4 and IPv6 addresses.
func GetPublicIPs() PublicIPs {
	var ips PublicIPs

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	if v4 := fetchIPString(client, "https://4.ipw.cn"); v4 != "" {
		ips.IPv4 = v4
	}

	if v6 := fetchIPString(client, "https://6.ipw.cn"); v6 != "" {
		ips.IPv6 = v6
	}

	return ips
}

func fetchIPString(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	ipStr := strings.TrimSpace(string(body))
	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}
