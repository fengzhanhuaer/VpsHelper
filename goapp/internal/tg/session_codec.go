package tg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
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
	s = unquoteSessionText(s)

	// If session text is already raw gotd JSON payload, return directly.
	if isGotdPayloadJSON([]byte(s)) {
		return []byte(s), nil
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
	var firstDecoded []byte
	for _, d := range decoders {
		b, err := d.enc.DecodeString(s)
		if err == nil {
			if isGotdPayloadJSON(b) {
				return b, nil
			}
			if firstDecoded == nil {
				firstDecoded = b
			}
			continue
		}
		lastErr = fmt.Errorf("%s: %w", d.name, err)
	}

	// Compat: accept Python Telethon StringSession and convert to gotd payload.
	buf, teleErr := decodeTelethonSessionText(s)
	if teleErr == nil {
		return buf, nil
	}

	if firstDecoded != nil {
		return firstDecoded, nil
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

func shouldRewriteSessionText(original string, decoded []byte) bool {
	return strings.TrimSpace(original) != encodeSessionText(decoded)
}

func isGotdPayloadJSON(b []byte) bool {
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	var probe struct {
		Version int
	}
	return json.Unmarshal(b, &probe) == nil && probe.Version > 0
}

func decodeTelethonSessionText(s string) ([]byte, error) {
	teleData, teleErr := gotdsession.TelethonSession(s)
	if teleErr != nil {
		padded := padTelethonString(s)
		if padded != s {
			teleData, teleErr = gotdsession.TelethonSession(padded)
		}
	}
	if teleErr != nil {
		return nil, teleErr
	}

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

func padTelethonString(s string) string {
	if len(s) < 2 || s[0] != '1' {
		return s
	}

	switch len(s[1:]) % 4 {
	case 0:
		return s
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

func unquoteSessionText(s string) string {
	if len(s) < 2 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		if unquoted, err := strconv.Unquote(s); err == nil {
			return unquoted
		}
		return s[1 : len(s)-1]
	}

	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}
