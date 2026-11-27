package sshproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newUnansweringServer starts an SSH server that completes the handshake and
// then never answers a request to open a channel, and returns its URL.
func newUnansweringServer(t *testing.T) string {
	t.Helper()
	privData, _ := genHostKey(t)
	key, err := openDatas([]string{privData})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key[0])
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				<-done
			}()
		}
	}()
	return "ssh://" + listener.Addr().String()
}

func TestDialIsBoundedByTimeout(t *testing.T) {
	dial, err := NewDialer(newUnansweringServer(t) + "?timeout=200ms")
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		conn, err := dial.Dial("tcp", "127.0.0.1:1")
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial error = %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
			t.Fatalf("Dial gave up after %v, before its 200ms timeout", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Dial still waits for an unanswered channel 5s after a 200ms timeout")
	}
}

func TestDialWithoutTimeoutKeepsWaiting(t *testing.T) {
	dial, err := NewDialer(newUnansweringServer(t) + "?timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := dial.Dial("tcp", "127.0.0.1:1")
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("Dial with timeout=0 returned while its channel is unanswered: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	dial.Close()
	select {
	case <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not return after its Dialer was closed")
	}
}

func TestDialWithinTimeoutSucceeds(t *testing.T) {
	dial := newTestDialer(t, "?timeout=5s")
	conn, err := dial.Dial("tcp", newEchoListener(t).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}
