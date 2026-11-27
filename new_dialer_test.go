package sshproxy

import (
	"context"
	"net/url"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNewDialerWithNilConfig(t *testing.T) {
	dial, err := NewDialerWithConfig("127.0.0.1:22", nil)
	if err == nil {
		t.Fatalf("NewDialerWithConfig accepted a nil config and returned %v", dial)
	}
}

func TestNewDialerWithConfigConnects(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := url.Parse(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	dial, err := NewDialerWithConfig(u.Host, &ssh.ClientConfig{
		User:            "u",
		Auth:            []ssh.AuthMethod{ssh.Password("p")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	conn, err := dial.DialContext(context.Background(), "tcp", newEchoListener(t).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}
