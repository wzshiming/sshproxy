package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"

	"golang.org/x/crypto/ssh"
)

var testServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("ok"))
}))

func TestBind(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	listener, err := dial.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go http.Serve(listener, nil)

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var resp *http.Response
	for i := 0; ; i++ {
		resp, err = http.Get("http://127.0.0.1:" + port)
		if err == nil {
			break
		}
		if i >= 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp.Body.Close()
}

func TestServer(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestDialerConnections(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL() + "?connections=2")
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	cli1, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	cli2, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cli1 == cli2 {
		t.Fatal("expected different ssh clients when pool is filling")
	}

	cli3, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cli3 != cli1 && cli3 != cli2 {
		t.Fatal("expected ssh client to be reused from pool")
	}
}

func newEchoListener(t *testing.T) net.Listener {
	t.Helper()
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
				if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					return
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		timer := time.AfterFunc(2*time.Second, func() { conn.Close() })
		defer timer.Stop()
	}
	message := "echo"
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatalf("echo write failed: %v", err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("echo read failed: %v", err)
	}
	if string(reply) != message {
		t.Fatalf("echo = %q, want %q", reply, message)
	}
}

func TestDialRejectedKeepsClient(t *testing.T) {
	ctx := context.Background()
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	listener := newEchoListener(t)
	conn, err := dial.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := dial.DialContext(ctx, "tcp", "127.0.0.1:1")
	if rejected != nil {
		rejected.Close()
	}
	var channelErr *ssh.OpenChannelError
	if !errors.As(err, &channelErr) {
		t.Fatalf("dial error = %v, want *ssh.OpenChannelError", err)
	}
	assertEcho(t, conn)
	cli2, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cli2 != cli1 {
		t.Fatal("rejected dial replaced the shared SSH client")
	}
}

func TestDialCanceledContextKeepsClient(t *testing.T) {
	ctx := context.Background()
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	listener := newEchoListener(t)
	conn, err := dial.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	canceled, err := dial.DialContext(canceledCtx, "tcp", listener.Addr().String())
	if canceled != nil {
		canceled.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want context.Canceled", err)
	}
	assertEcho(t, conn)
	cli2, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cli2 != cli1 {
		t.Fatal("canceled dial replaced the shared SSH client")
	}
}

func TestClosedClientIsReplaced(t *testing.T) {
	ctx := context.Background()
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli1.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		cli2, err := dial.SSHClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cli2 != nil && cli2 != cli1 {
			listener := newEchoListener(t)
			conn, err := cli2.DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			assertEcho(t, conn)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("closed SSH client remained in the pool for 2 seconds")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type pausableConn struct {
	net.Conn
	paused    *atomic.Bool
	closed    chan struct{}
	closeOnce sync.Once
}

func (conn *pausableConn) Read(data []byte) (int, error) {
	count, err := conn.Conn.Read(data)
	for conn.paused.Load() {
		select {
		case <-conn.closed:
			return 0, net.ErrClosed
		case <-time.After(time.Millisecond):
		}
	}
	return count, err
}

func (conn *pausableConn) Write(data []byte) (int, error) {
	if conn.paused.Load() {
		return len(data), nil
	}
	return conn.Conn.Write(data)
}

func (conn *pausableConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.closed) })
	return conn.Conn.Close()
}

func TestKeepAliveClosesUnresponsiveTransport(t *testing.T) {
	ctx := context.Background()
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dial, err := NewDialer(s.ProxyURL() + "?keepalive=50ms")
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	var paused, wrapped atomic.Bool
	var proxyDialer net.Dialer
	dial.ProxyDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := proxyDialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if !wrapped.CompareAndSwap(false, true) {
			return conn, nil
		}
		return &pausableConn{Conn: conn, paused: &paused, closed: make(chan struct{})}, nil
	}
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	paused.Store(true)
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		cli2, err := dial.SSHClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cli2 != nil && cli2 != cli1 {
			listener := newEchoListener(t)
			conn, err := cli2.DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			assertEcho(t, conn)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("unresponsive SSH client remained in the pool after 10 keepalive intervals")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKeepAliveKeepsHealthyTransport(t *testing.T) {
	ctx := context.Background()
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dial, err := NewDialer(s.ProxyURL() + "?keepalive=100ms")
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := cli1.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected the test server to reject the keepalive request")
	}
	time.Sleep(550 * time.Millisecond)
	cli2, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cli2 != cli1 {
		t.Fatal("keepalive replaced a healthy SSH client")
	}
	listener := newEchoListener(t)
	conn, err := cli2.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

func TestParseKeepAlive(t *testing.T) {
	for _, test := range []struct {
		name    string
		query   string
		want    time.Duration
		wantErr bool
	}{
		{name: "absent"},
		{name: "zero", query: "?keepalive=0"},
		{name: "seconds", query: "?keepalive=30s", want: 30 * time.Second},
		{name: "milliseconds", query: "?keepalive=50ms", want: 50 * time.Millisecond},
		{name: "invalid", query: "?keepalive=abc", wantErr: true},
		{name: "negative", query: "?keepalive=-1s", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := parseClientConfig("ssh://u:p@h:22" + test.query)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an invalid keepalive error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.keepAlive != test.want {
				t.Fatalf("keepalive = %v, want %v", config.keepAlive, test.want)
			}
		})
	}
}

func genHostKey(t *testing.T) (privData, pubData string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privData = base64.URLEncoding.EncodeToString(pem.EncodeToMemory(pemBlock))
	pubData = base64.URLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(sshPub))
	return privData, pubData
}

func TestHostKeyVerify(t *testing.T) {
	privData, pubData := genHostKey(t)

	s, err := NewSimpleServer("ssh://u:p@:0?hostkey_data=" + privData)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL() + "?hostkey_data=" + pubData)
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	_, err = dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	_, otherPubData := genHostKey(t)
	badDial, err := NewDialer(s.ProxyURL() + "?hostkey_data=" + otherPubData)
	if err != nil {
		t.Fatal(err)
	}
	defer badDial.Close()

	_, err = badDial.SSHClient(context.Background())
	if err == nil {
		t.Fatal("expected host key mismatch error")
	}
}
