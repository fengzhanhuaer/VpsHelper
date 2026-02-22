// Package ns implements NodeSeek lottery monitoring.
package ns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// LotteryParams parsed from a nodeseek lucky URL.
type LotteryParams struct {
	PostID     string
	DrawTimeMs int64 // milliseconds
	Count      int
	StartFloor int
	Duplicate  bool
}

// ParseLotteryURL extracts lottery parameters from a nodeseek lucky URL.
func ParseLotteryURL(rawURL string) (LotteryParams, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return LotteryParams{}, fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()

	postID := strings.TrimSpace(q.Get("post"))
	if postID == "" {
		return LotteryParams{}, fmt.Errorf("missing post parameter")
	}

	timeMs, err := strconv.ParseInt(strings.TrimSpace(q.Get("time")), 10, 64)
	if err != nil || timeMs <= 0 {
		return LotteryParams{}, fmt.Errorf("invalid time parameter")
	}

	count, _ := strconv.Atoi(q.Get("count"))
	if count <= 0 {
		count = 1
	}
	start, _ := strconv.Atoi(q.Get("start"))
	if start < 0 {
		start = 0
	}
	dup := strings.EqualFold(q.Get("duplicate"), "true")

	return LotteryParams{
		PostID:     postID,
		DrawTimeMs: timeMs,
		Count:      count,
		StartFloor: start,
		Duplicate:  dup,
	}, nil
}

// LotteryResult holds the scraped result from the NodeSeek lucky page.
type LotteryResult struct {
	Winners []string // winner usernames
	IsWon   bool     // whether watchUsername is among winners
	Note    string   // summary text
}

// CheckResult visits the NodeSeek lucky page and scrapes the winner list.
// It returns the winners and whether watchUsername (case-insensitive) is among them.
func CheckResult(ctx context.Context, luckyURL string, watchUsername string) (LotteryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, luckyURL, nil)
	if err != nil {
		return LotteryResult{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://www.nodeseek.com/")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false, // Force HTTP/1.1 to bypass simple CF TLS fingerprint
			TLSClientConfig: &tls.Config{
				MaxVersion: tls.VersionTLS13,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return LotteryResult{}, fmt.Errorf("fetch lucky page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LotteryResult{}, fmt.Errorf("read body: %w", err)
	}
	html := string(body)

	// The NodeSeek lucky page renders winners using JavaScript.
	// The page includes __NUXT_DATA__ or similar embedded JSON with result data.
	// We try multiple strategies to extract winner names.

	winners := extractWinnersFromHTML(html)

	if len(winners) == 0 {
		// If we can't parse from HTML (JS-rendered), return error to retry later.
		if resp.StatusCode == 403 {
			return LotteryResult{}, fmt.Errorf("nodeseek returned 403, may need retry")
		}
		// Page loaded but no winners found — could be JS-rendered or not yet drawn.
		return LotteryResult{}, fmt.Errorf("无法从页面解析中奖名单，页面可能尚未渲染完成")
	}

	watchLower := strings.ToLower(strings.TrimSpace(watchUsername))
	isWon := false
	for _, w := range winners {
		if watchLower != "" && strings.ToLower(w) == watchLower {
			isWon = true
			break
		}
	}

	note := fmt.Sprintf("中奖名单: %s", strings.Join(winners, "、"))

	return LotteryResult{
		Winners: winners,
		IsWon:   isWon,
		Note:    note,
	}, nil
}

// extractWinnersFromHTML tries to parse winner names from the lucky page HTML.
// NodeSeek renders winners in a table; the member names appear as links like:
//
//	<a href="/space/12345">Username</a>
//
// within the winner list section.
func extractWinnersFromHTML(html string) []string {
	// Strategy 1: Look for the winner table rows.
	// The winner list has links to /space/XXXXX with the username as text.
	re := regexp.MustCompile(`/space/\d+"[^>]*>([^<]+)</a>`)
	matches := re.FindAllStringSubmatch(html, -1)

	var winners []string
	seen := map[string]bool{}
	for _, m := range matches {
		name := strings.TrimSpace(m[1])
		if name != "" && !seen[name] {
			winners = append(winners, name)
			seen[name] = true
		}
	}

	if len(winners) > 0 {
		return winners
	}

	// Strategy 2: Look for __NUXT_DATA__ or embedded JSON with member_name.
	re2 := regexp.MustCompile(`"member_name"\s*:\s*"([^"]+)"`)
	matches2 := re2.FindAllStringSubmatch(html, -1)
	for _, m := range matches2 {
		name := strings.TrimSpace(m[1])
		if name != "" && !seen[name] {
			winners = append(winners, name)
			seen[name] = true
		}
	}

	return winners
}
