package sshproxy

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newExecServer starts an SSH server that answers every exec request by
// writing fixed text to the command's stdout and stderr, and returns its URL.
func newExecServer(t *testing.T, stdout, stderr string) string {
	t.Helper()
	signer, err := ssh.ParsePrivateKey(decodeTestKey(t))
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
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					ch, chReqs, err := newChan.Accept()
					if err != nil {
						return
					}
					go func() {
						defer ch.Close()
						for req := range chReqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							req.Reply(true, nil)
							io.WriteString(ch, stdout)
							io.WriteString(ch.Stderr(), stderr)
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	return "ssh://" + listener.Addr().String()
}

func decodeTestKey(t *testing.T) []byte {
	t.Helper()
	privData, _ := genHostKey(t)
	key, err := openDatas([]string{privData})
	if err != nil {
		t.Fatal(err)
	}
	return key[0]
}

// syncBuffer is a strings.Builder safe to write from the session's copy goroutine.
type syncBuffer struct {
	mut sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mut.Lock()
	defer b.mut.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mut.Lock()
	defer b.mut.Unlock()
	return b.buf.String()
}

func TestCommandStderrGoesToDialerStderr(t *testing.T) {
	dial, err := NewDialer(newExecServer(t, "to-stdout\n", "to-stderr\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	var stderr syncBuffer
	dial.Stderr = &stderr
	conn, err := dial.CommandDialContext(context.Background(), "anything")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	stdout, _ := io.ReadAll(conn)
	if got := string(stdout); got != "to-stdout\n" {
		t.Fatalf("stdout = %q, want %q", got, "to-stdout\n")
	}
	deadline := time.Now().Add(2 * time.Second)
	for stderr.String() != "to-stderr\n" {
		if time.Now().After(deadline) {
			t.Fatalf("Dialer.Stderr received %q, want %q", stderr.String(), "to-stderr\n")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
