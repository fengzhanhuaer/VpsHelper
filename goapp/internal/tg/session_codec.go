package tg

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// decodeSessionText accepts both standard and URL-safe base64 encodings
// (with or without padding) to support historical stored values.
func decodeSessionText(sessionText string) ([]byte, error) {
	s := strings.TrimSpace(sessionText)
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

	return nil, lastErr
}

func encodeSessionText(data []byte) string {
	// URL-safe without padding keeps storage compact and shell-friendly.
	return base64.RawURLEncoding.EncodeToString(data)
}
