package sshproxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// connectedClient returns an SSH client connected to the server, with a
// forwarded connection open through it.
func connectedClient(t *testing.T, s *SimpleServer) *ssh.Client {
	t.Helper()
	dial, err := NewDialer(s.ProxyURL() + "?keepalive=0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dial.Close() })
	conn, err := dial.DialContext(context.Background(), "tcp", newEchoListener(t).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	assertEcho(t, conn)
	cli, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func assertDisconnected(t *testing.T, cli *ssh.Client, when string) {
	t.Helper()
	gone := make(chan struct{})
	go func() {
		cli.Wait()
		close(gone)
	}()
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		t.Fatalf("client is still connected 2s after %s", when)
	}
}

func assertRefusesClients(t *testing.T, s *SimpleServer, when string) {
	t.Helper()
	dial, err := NewDialer(s.ProxyURL() + "?timeout=2s")
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	if _, err := dial.SSHClient(context.Background()); err == nil {
		t.Fatalf("server accepted a client after %s", when)
	}
}

func TestSimpleServerCloseDisconnectsClients(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	cli := connectedClient(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertDisconnected(t, cli, "Close")
	assertRefusesClients(t, s, "Close")
}

func TestSimpleServerRunEndsWithContext(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Listen first so the address is known before Run blocks.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := s.listen(ctx); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- s.Run(ctx) }()
	cli := connectedClient(t, s)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run is still serving 2s after its context ended")
	}
	assertDisconnected(t, cli, "the context of Run ended")
	assertRefusesClients(t, s, "the context of Run ended")
}

func TestSimpleServerStartOutlivesItsContext(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cancel()
	connectedClient(t, s)
}

func TestSimpleServerForgetsClosedConnections(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cli := connectedClient(t, s)
	cli.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mut.Lock()
		tracked := len(s.conns)
		s.mut.Unlock()
		if tracked == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server still tracks %d connections after its only client left", tracked)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
