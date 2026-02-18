package tg

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"testing"

	gotdsession "github.com/gotd/td/session"
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

type staticSessionStorage struct {
	data []byte
}

func (s staticSessionStorage) LoadSession(_ context.Context) ([]byte, error) {
	return s.data, nil
}

func (s staticSessionStorage) StoreSession(_ context.Context, _ []byte) error {
	return nil
}

func TestDecodeSessionText_AcceptsTelethonStringSession(t *testing.T) {
	payload := make([]byte, 263)
	payload[0] = 2 // dc id
	copy(payload[1:5], []byte{149, 154, 167, 51})
	binary.BigEndian.PutUint16(payload[5:7], 443)
	for i := 7; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	telethon := "1" + base64.URLEncoding.EncodeToString(payload)
	got, err := decodeSessionText(telethon)
	if err != nil {
		t.Fatalf("decode telethon string failed: %v", err)
	}

	loader := gotdsession.Loader{Storage: staticSessionStorage{data: got}}
	data, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("load converted gotd payload failed: %v", err)
	}

	if data.DC != 2 {
		t.Fatalf("unexpected dc: %d", data.DC)
	}
	if len(data.AuthKey) != 256 {
		t.Fatalf("unexpected auth key len: %d", len(data.AuthKey))
	}
}
