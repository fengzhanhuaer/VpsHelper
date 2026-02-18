package tg

import (
	"encoding/base64"
	"testing"
)

func TestDecodeSessionText_AcceptsURLAndStdBase64(t *testing.T) {
	original := []byte("session-binary-\x00-\x01-\x02")

	cases := []string{
		base64.StdEncoding.EncodeToString(original),
		base64.RawStdEncoding.EncodeToString(original),
		base64.URLEncoding.EncodeToString(original),
		base64.RawURLEncoding.EncodeToString(original),
	}

	for _, encoded := range cases {
		got, err := decodeSessionText(encoded)
		if err != nil {
			t.Fatalf("decode failed for %q: %v", encoded, err)
		}
		if string(got) != string(original) {
			t.Fatalf("decoded mismatch for %q", encoded)
		}
	}
}

func TestEncodeSessionText_UsesRawURLBase64(t *testing.T) {
	encoded := encodeSessionText([]byte{0xff, 0xfe, 0xfd})
	if encoded == "" {
		t.Fatal("encoded should not be empty")
	}
	if _, err := base64.RawURLEncoding.DecodeString(encoded); err != nil {
		t.Fatalf("encoded value should be raw url-base64: %v", err)
	}
}
