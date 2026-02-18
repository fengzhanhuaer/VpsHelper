package tg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	gotdsession "github.com/gotd/td/session"
)

// decodeSessionText accepts both standard and URL-safe base64 encodings
// (with or without padding) to support historical stored values.
func decodeSessionText(sessionText string) ([]byte, error) {
	s := strings.TrimSpace(sessionText)
	if s == "" {
		return nil, fmt.Errorf("empty session text")
	}

	// If session text is already raw gotd JSON payload, return directly.
	if strings.HasPrefix(s, "{") {
		var probe struct {
			Version int
		}
		if err := json.Unmarshal([]byte(s), &probe); err == nil && probe.Version > 0 {
			return []byte(s), nil
		}
	}

	decoders := []struct {
		name string
		enc  *base64.Encoding
	}{
		{name: "raw-url", enc: base64.RawURLEncoding},
		{name: "url", enc: base64.URLEncoding},
		{name: "raw-std", enc: base64.RawStdEncoding},
		{name: "std", enc: base64.StdEncoding},
	}

	var lastErr error
	for _, d := range decoders {
		b, err := d.enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		lastErr = fmt.Errorf("%s: %w", d.name, err)
	}

	// Compat: accept Python Telethon StringSession and convert to gotd payload.
	teleData, teleErr := gotdsession.TelethonSession(s)
	if teleErr == nil {
		buf, err := json.Marshal(struct {
			Version int
			Data    gotdsession.Data
		}{
			Version: 1,
			Data:    *teleData,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal telethon session: %w", err)
		}
		return buf, nil
	}

	if lastErr == nil {
		return nil, teleErr
	}
	return nil, fmt.Errorf("%v; telethon: %w", lastErr, teleErr)
}

func encodeSessionText(data []byte) string {
	// URL-safe without padding keeps storage compact and shell-friendly.
	return base64.RawURLEncoding.EncodeToString(data)
}
