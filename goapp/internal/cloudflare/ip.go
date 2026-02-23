package cloudflare

import (
	"context"
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

	clientV4 := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp4", addr)
			},
		},
	}
	if v4 := fetchIP(clientV4); v4 != "" {
		ips.IPv4 = v4
	}

	clientV6 := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp6", addr)
			},
		},
	}
	if v6 := fetchIP(clientV6); v6 != "" {
		ips.IPv6 = v6
	}

	return ips
}

func fetchIP(client *http.Client) string {
	// 1.1.1.1 is accessible via both IPv4 and IPv6 routing (as 2606:4700:4700::1111 if via tcp6 domain)
	// but to be absolutely sure, we use the v4 and v6 specific trace endpoints if available,
	// or we just use api.ipify.org and api6.ipify.org
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		}
	}
	return ""
}
