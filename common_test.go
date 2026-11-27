package sshproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"testing"
)

func TestDecodeBase64AcceptsEveryVariant(t *testing.T) {
	// Lengths 0 to 5 cover every padding; the bytes use the characters in
	// which the two alphabets differ.
	for _, data := range [][]byte{
		{},
		{0xfb},
		{0xfb, 0xff},
		{0xfb, 0xff, 0xbe},
		{0xfb, 0xff, 0xbe, 0xfe},
		{0xfb, 0xff, 0xbe, 0xfe, 0x3e},
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----\n"),
	} {
		for name, encoding := range map[string]*base64.Encoding{
			"URL-safe":          base64.URLEncoding,
			"URL-safe unpadded": base64.RawURLEncoding,
			"standard":          base64.StdEncoding,
			"standard unpadded": base64.RawStdEncoding,
		} {
			encoded := encoding.EncodeToString(data)
			got, err := decodeBase64(encoded)
			if err != nil || !bytes.Equal(got, data) {
				t.Errorf("%s %q decoded to %x, %v; want %x", name, encoded, got, err, data)
			}
		}
	}
}

func TestDecodeBase64RejectsInvalid(t *testing.T) {
	for _, encoded := range []string{"!!!!", "a", "ab=c", "a$b"} {
		if got, err := decodeBase64(encoded); err == nil {
			t.Errorf("%q decoded to %x, want an error", encoded, got)
		}
	}
}

// The standard alphabet survives a query string whether or not it is escaped.
func TestIdentityDataInStandardBase64(t *testing.T) {
	privData, pubData := genHostKey(t)
	priv, err := base64.URLEncoding.DecodeString(privData)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSimpleServer("ssh://127.0.0.1:0?authorized_data=" + pubData)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	standard := base64.StdEncoding.EncodeToString(priv)
	for name, query := range map[string]string{
		"escaped":   url.QueryEscape(standard),
		"unescaped": standard,
		"unpadded":  base64.RawURLEncoding.EncodeToString(priv),
	} {
		dial, err := NewDialer("ssh://user@" + s.Address + "?identity_data=" + query)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = dial.SSHClient(context.Background())
		dial.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
