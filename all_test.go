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
	"runtime"
	"slices"
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

func newTestDialer(t *testing.T, query string) *Dialer {
	t.Helper()
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	dial, err := NewDialer(s.ProxyURL() + query)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dial.Close() })
	return dial
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

func TestDialInvalidAddressKeepsClient(t *testing.T) {
	ctx := context.Background()
	dial := newTestDialer(t, "")
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
	invalid, err := dial.DialContext(ctx, "tcp", "no-port")
	if invalid != nil {
		invalid.Close()
	}
	var addrErr *net.AddrError
	if !errors.As(err, &addrErr) {
		t.Fatalf("dial error = %v, want *net.AddrError", err)
	}
	assertEcho(t, conn)
	cli2, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cli2 != cli1 {
		t.Fatal("dial to an unparsable address replaced the shared SSH client")
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
	cli2, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cli2 == cli1 {
		t.Fatal("closed SSH client was handed out again")
	}
	listener := newEchoListener(t)
	conn, err := cli2.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

// dialLog is a ProxyDial hook that keeps the connection of every call, nil for a failed one.
type dialLog struct {
	mut   sync.Mutex
	conns []net.Conn
}

func (l *dialLog) dial(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, address)
	l.mut.Lock()
	defer l.mut.Unlock()
	l.conns = append(l.conns, conn)
	return conn, err
}

func (l *dialLog) dialed() []net.Conn {
	l.mut.Lock()
	defer l.mut.Unlock()
	return slices.Clone(l.conns)
}

func TestRedialAfterTransportDropped(t *testing.T) {
	for _, test := range []struct {
		name string
		dial func(ctx context.Context, dial *Dialer, address string) (net.Conn, error)
	}{
		{name: "DialContext", dial: func(ctx context.Context, dial *Dialer, address string) (net.Conn, error) {
			return dial.DialContext(ctx, "tcp", address)
		}},
		{name: "SSHClient", dial: func(ctx context.Context, dial *Dialer, address string) (net.Conn, error) {
			cli, err := dial.SSHClient(ctx)
			if err != nil {
				return nil, err
			}
			return cli.DialContext(ctx, "tcp", address)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			dial := newTestDialer(t, "")
			var dials dialLog
			dial.ProxyDial = dials.dial
			address := newEchoListener(t).Addr().String()
			conn, err := test.dial(ctx, dial, address)
			if err != nil {
				t.Fatal(err)
			}
			assertEcho(t, conn)
			conn.Close()
			dials.dialed()[0].Close()
			if conn, err := test.dial(ctx, dial, address); err == nil {
				conn.Close()
			}
			conn, err = test.dial(ctx, dial, address)
			if err != nil {
				t.Fatalf("dial after the transport dropped and one dial failed: %v", err)
			}
			defer conn.Close()
			assertEcho(t, conn)
			if got := len(dials.dialed()); got != 2 {
				t.Fatalf("ProxyDial calls = %d, want 2", got)
			}
		})
	}
}

func TestClosedClientIsReplacedInPool(t *testing.T) {
	ctx := context.Background()
	dial := newTestDialer(t, "?connections=2")
	var dials dialLog
	dial.ProxyDial = dials.dial
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial.SSHClient(ctx); err != nil {
		t.Fatal(err)
	}
	address := newEchoListener(t).Addr().String()
	if err := cli1.Close(); err != nil {
		t.Fatal(err)
	}
	taken := map[*ssh.Client]bool{}
	for i := 1; i <= 4; i++ {
		cli, err := dial.SSHClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cli == cli1 {
			t.Fatalf("take %d handed out the closed SSH client", i)
		}
		conn, err := cli.DialContext(ctx, "tcp", address)
		if err != nil {
			t.Fatalf("take %d handed out an unusable SSH client: %v", i, err)
		}
		assertEcho(t, conn)
		conn.Close()
		taken[cli] = true
	}
	if len(taken) != 2 {
		t.Fatalf("distinct SSH clients handed out = %d, want 2", len(taken))
	}
	if got := len(dials.dialed()); got != 3 {
		t.Fatalf("ProxyDial calls = %d, want 3", got)
	}
}

// brokenWriteConn fails its writes once broken is set, while its reads keep blocking.
type brokenWriteConn struct {
	net.Conn
	broken *atomic.Bool
}

func (conn *brokenWriteConn) Write(data []byte) (int, error) {
	if conn.broken.Load() {
		return 0, io.ErrClosedPipe
	}
	return conn.Conn.Write(data)
}

func TestWriteFailureReplacesAndClosesClient(t *testing.T) {
	ctx := context.Background()
	dial := newTestDialer(t, "")
	var broken, wrapped atomic.Bool
	var proxyDialer net.Dialer
	dial.ProxyDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := proxyDialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if !wrapped.CompareAndSwap(false, true) {
			return conn, nil
		}
		return &brokenWriteConn{Conn: conn, broken: &broken}, nil
	}
	cli1, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	dialCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	conn, err := dial.DialContext(dialCtx, "tcp", newEchoListener(t).Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("dial over a transport whose writes fail succeeded")
	}
	cli2, err := dial.SSHClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cli2 == cli1 {
		t.Fatal("SSH client whose transport failed a write was handed out again")
	}
	closed := make(chan struct{})
	go func() {
		cli1.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("replaced SSH client was not closed within 1 second")
	}
}

func TestReplacedClientsLeaveNoGoroutines(t *testing.T) {
	ctx := context.Background()
	dial := newTestDialer(t, "?keepalive=1h")
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		cli, err := dial.SSHClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := cli.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := dial.SSHClient(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := dial.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+5 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after closing the dialer, want at most %d", runtime.NumGoroutine(), before+5)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDialerCloseIgnoresEndedClient(t *testing.T) {
	dial := newTestDialer(t, "")
	cli, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dial.Close(); err != nil {
		t.Fatalf("closing a dialer whose only client was already closed: %v", err)
	}
}

func TestConnRecordCountsArrivedBytes(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	record := newConnRecord(local)
	if got := record.arrived(); got != 0 {
		t.Fatalf("bytes arrived before any read = %d, want 0", got)
	}
	go remote.Write([]byte("hello"))
	for _, size := range []int{2, 3} {
		if _, err := io.ReadFull(record, make([]byte, size)); err != nil {
			t.Fatal(err)
		}
	}
	if got := record.arrived(); got != 5 {
		t.Fatalf("bytes arrived after reading 2 and 3 bytes = %d, want 5", got)
	}
}

// closeHookConn calls onClose as its Close begins.
type closeHookConn struct {
	net.Conn
	onClose func()
}

func (conn *closeHookConn) Close() error {
	conn.onClose()
	return conn.Conn.Close()
}

func TestConnRecordEndsOnlyAfterClosingItsConnection(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	var record *connRecord
	record = newConnRecord(&closeHookConn{Conn: local, onClose: func() {
		if record.ended() {
			t.Error("record read as ended while its connection was closing")
		}
		select {
		case <-record.done():
			t.Error("record notified its end while its connection was closing")
		default:
		}
	}})
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConnRecordEnds(t *testing.T) {
	for _, test := range []struct {
		name string
		end  func(t *testing.T, record *connRecord, remote net.Conn)
	}{
		{name: "read error", end: func(t *testing.T, record *connRecord, remote net.Conn) {
			remote.Close()
			if _, err := record.Read(make([]byte, 1)); err == nil {
				t.Fatal("read from a closed pipe succeeded")
			}
		}},
		{name: "write error", end: func(t *testing.T, record *connRecord, remote net.Conn) {
			remote.Close()
			if _, err := record.Write([]byte{0}); err == nil {
				t.Fatal("write to a closed pipe succeeded")
			}
		}},
		{name: "close", end: func(t *testing.T, record *connRecord, remote net.Conn) {
			if err := record.Close(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			record := newConnRecord(local)
			if record.ended() {
				t.Fatal("open connection reads as ended")
			}
			select {
			case <-record.done():
				t.Fatal("open connection notified its end")
			default:
			}
			test.end(t, record, remote)
			if !record.ended() {
				t.Fatal("connection does not read as ended")
			}
			select {
			case <-record.done():
			default:
				t.Fatal("connection did not notify its end")
			}
		})
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
