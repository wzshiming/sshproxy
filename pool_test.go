package sshproxy

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
)

// poolLoads returns the connections open through each pooled client, sorted.
func poolLoads(d *Dialer) []int64 {
	d.mut.Lock()
	defer d.mut.Unlock()
	loads := make([]int64, 0, len(d.sshCli))
	for _, sshCli := range d.sshCli {
		loads = append(loads, sshCli.active.Load())
	}
	slices.Sort(loads)
	return loads
}

func assertPoolLoads(t *testing.T, d *Dialer, when string, want ...int64) {
	t.Helper()
	if got := poolLoads(d); !slices.Equal(got, want) {
		t.Fatalf("%s: connections per pooled client = %v, want %v", when, got, want)
	}
}

// newFullPoolDialer returns a Dialer whose pool of two clients is already dialed.
func newFullPoolDialer(t *testing.T) *Dialer {
	t.Helper()
	dial := newTestDialer(t, "?connections=2")
	for range 2 {
		if _, err := dial.SSHClient(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return dial
}

func TestDialPrefersLeastLoadedClient(t *testing.T) {
	dial := newFullPoolDialer(t)
	address := newEchoListener(t).Addr().String()
	open := func() net.Conn {
		t.Helper()
		conn, err := dial.DialContext(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	first, second := open(), open()
	assertPoolLoads(t, dial, "after two dials", 1, 1)

	// Empty one client; it must take every dial until it has caught up.
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	assertPoolLoads(t, dial, "after closing one connection", 0, 1)
	open()
	assertPoolLoads(t, dial, "after one more dial", 1, 1)
	open()
	open()
	assertPoolLoads(t, dial, "after three more dials", 2, 2)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	first.Close()
	assertPoolLoads(t, dial, "after closing a connection twice", 1, 2)
	open()
	assertPoolLoads(t, dial, "after a dial into the gap", 2, 2)
}

func TestDialWithoutContextIsCounted(t *testing.T) {
	dial := newFullPoolDialer(t)
	conn, err := dial.Dial("tcp", newEchoListener(t).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	assertPoolLoads(t, dial, "after Dial", 0, 1)
	assertEcho(t, conn)
	conn.Close()
	assertPoolLoads(t, dial, "after closing its connection", 0, 0)
}

func TestFailedDialIsNotCounted(t *testing.T) {
	dial := newFullPoolDialer(t)
	if conn, err := dial.DialContext(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("dial to a closed port succeeded")
	}
	assertPoolLoads(t, dial, "after a rejected dial", 0, 0)
}

func TestIdlePoolTakesClientsInTurn(t *testing.T) {
	dial := newFullPoolDialer(t)
	cli1, _ := dial.SSHClient(context.Background())
	cli2, _ := dial.SSHClient(context.Background())
	cli3, _ := dial.SSHClient(context.Background())
	if cli1 == cli2 || cli3 != cli1 {
		t.Fatal("equally loaded clients were not handed out in turn")
	}
}

func TestDialedConnKeepsCloseWrite(t *testing.T) {
	dial := newTestDialer(t, "")
	conn, err := dial.DialContext(context.Background(), "tcp", newEchoListener(t).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	halfCloser, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T has no CloseWrite", conn)
	}
	assertEcho(t, conn)
	if err := halfCloser.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "more"); err == nil {
		t.Fatal("write succeeded after CloseWrite")
	}
}
