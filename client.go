package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultKeepAlive time.Duration = 30 * time.Second

// NewDialer returns a new Dialer that dials through the provided
// proxy server's network and address.
func NewDialer(addr string) (*Dialer, error) {
	config, err := parseClientConfig(addr)
	if err != nil {
		return nil, err
	}
	d, err := NewDialerWithConfig(config.host, config.clientConfig)
	if err != nil {
		return nil, err
	}
	d.Connections = config.connections
	d.KeepAlive = config.keepAlive
	return d, nil
}

func NewDialerWithConfig(host string, config *ssh.ClientConfig) (*Dialer, error) {
	return &Dialer{
		host:        host,
		config:      config,
		Connections: 1,
		KeepAlive:   defaultKeepAlive,
	}, nil
}

type clientConfig struct {
	host         string
	clientConfig *ssh.ClientConfig
	connections  int
	keepAlive    time.Duration
}

func parseClientConfig(addr string) (*clientConfig, error) {
	ur, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	user := ""
	pwd := ""
	isPwd := false
	if ur.User != nil {
		user = ur.User.Username()
		pwd, isPwd = ur.User.Password()
	}

	config := &ssh.ClientConfig{
		User: user,
		// Insecure by default, overridden below when hostkey_data or
		// hostkey_file is provided.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if isPwd {
		config.Auth = append(config.Auth, ssh.Password(pwd))
	}

	// hostkey_data and hostkey_file hold the server's public host keys
	// in authorized_keys format used to verify the server.
	hostkeyDatas, err := getQuery(ur.Query()["hostkey_data"], ur.Query()["hostkey_file"])
	if err != nil {
		return nil, err
	}
	if len(hostkeyDatas) != 0 {
		var hostKeys []ssh.PublicKey
		for _, data := range hostkeyDatas {
			keys, err := parseAuthorizedKeys(data)
			if err != nil {
				return nil, err
			}
			hostKeys = append(hostKeys, keys...)
		}
		config.HostKeyCallback = fixedHostKeys(hostKeys)
	}

	identityDatas, err := getQuery(ur.Query()["identity_data"], ur.Query()["identity_file"])
	if err != nil {
		return nil, err
	}
	for _, data := range identityDatas {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	var timeout = 30 * time.Second
	timeoutStr := ur.Query().Get("timeout")
	if timeoutStr != "" {
		timeout, err = time.ParseDuration(timeoutStr)
		if err != nil || timeout < 0 {
			return nil, fmt.Errorf("invalid timeout: %q", timeoutStr)
		}
	}

	config.Timeout = timeout

	keepAlive := defaultKeepAlive
	keepAliveStr := ur.Query().Get("keepalive")
	if keepAliveStr != "" {
		keepAlive, err = time.ParseDuration(keepAliveStr)
		if err != nil || keepAlive < 0 {
			return nil, fmt.Errorf("invalid keepalive: %q", keepAliveStr)
		}
	}

	connections := 1
	connectionsStr := ur.Query().Get("connections")
	if connectionsStr != "" {
		connections, err = strconv.Atoi(connectionsStr)
		if err != nil || connections <= 0 {
			return nil, fmt.Errorf("invalid connections: %q", connectionsStr)
		}
	}

	host := ur.Hostname()
	port := ur.Port()
	if port == "" {
		port = "22"
	}

	return &clientConfig{
		clientConfig: config,
		host:         net.JoinHostPort(host, port),
		connections:  connections,
		keepAlive:    keepAlive,
	}, nil
}

func parseAuthorizedKeys(data []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for len(bytes.TrimSpace(data)) > 0 {
		key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
		data = rest
	}
	return keys, nil
}

func fixedHostKeys(keys []ssh.PublicKey) ssh.HostKeyCallback {
	marshaled := make([][]byte, 0, len(keys))
	for _, key := range keys {
		marshaled = append(marshaled, key.Marshal())
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := key.Marshal()
		for _, want := range marshaled {
			if bytes.Equal(got, want) {
				return nil
			}
		}
		return fmt.Errorf("ssh: no matching host key for %q", hostname)
	}
}

type Dialer struct {
	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
	// Connections is the maximum number of SSH transport connections maintained.
	// Values less than or equal to 0 are treated as 1.
	Connections int
	// KeepAlive is the interval between keepalive@openssh.com global requests on
	// every pooled client. A client is closed if a request errors, or if a whole
	// interval passes with neither its reply nor any byte arriving. Zero disables
	// keepalives; the default is 30s.
	KeepAlive time.Duration
	// Stderr receives the standard error of commands run by CommandDialContext.
	// If nil, os.Stderr is used; set it to io.Discard to drop the output.
	Stderr io.Writer

	host   string
	config *ssh.ClientConfig

	mut     sync.Mutex
	sshCli  []pooledClient
	next    int
	dialing int           // clients being dialed outside mut
	dialed  chan struct{} // non-nil while a caller waits; closed as a dial finishes
	closes  int           // times Close ran, to discard clients dialed across it
}

type pooledClient struct {
	*ssh.Client
	record *connRecord
	active *atomic.Int64 // connections the Dialer has open through the client
}

func (d *Dialer) Close() error {
	d.mut.Lock()
	defer d.mut.Unlock()
	d.closes++
	d.purgeEnded()
	if len(d.sshCli) == 0 {
		return nil
	}

	var firstErr error
	for _, sshCli := range d.sshCli {
		err := sshCli.Close()
		if firstErr == nil {
			firstErr = err
		}
	}

	d.sshCli = nil
	d.next = 0
	return firstErr
}

func (d *Dialer) connections() int {
	if d.Connections <= 0 {
		return 1
	}
	return d.Connections
}

func (d *Dialer) closeSSHClient(sshCli *ssh.Client) error {
	if sshCli == nil {
		return nil
	}

	d.mut.Lock()
	defer d.mut.Unlock()

	for i := range d.sshCli {
		if d.sshCli[i].Client != sshCli {
			continue
		}

		err := d.sshCli[i].Close()
		d.sshCli = append(d.sshCli[:i], d.sshCli[i+1:]...)
		if len(d.sshCli) == 0 {
			d.next = 0
		} else {
			d.next %= len(d.sshCli)
		}
		return err
	}

	return sshCli.Close()
}

// purgeEnded requires d.mut to be held.
func (d *Dialer) purgeEnded() {
	d.sshCli = slices.DeleteFunc(d.sshCli, func(sshCli pooledClient) bool {
		ended := sshCli.record.ended()
		if ended {
			sshCli.Close()
		}
		return ended
	})
}

func (d *Dialer) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := d.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}

// SSHClient returns a pooled SSH client, dialing a new one while the pool is
// below Connections. A full pool hands out the client with the fewest
// connections opened through the Dialer, taking equally loaded clients in turn. Dialing does not block callers a pooled client can serve.
func (d *Dialer) SSHClient(ctx context.Context) (*ssh.Client, error) {
	d.mut.Lock()
	for {
		d.purgeEnded()
		connections := d.connections()
		if len(d.sshCli) > 0 && len(d.sshCli)+d.dialing >= connections {
			idx := d.leastLoaded()
			d.next = (idx + 1) % len(d.sshCli)
			sshCli := d.sshCli[idx].Client
			d.mut.Unlock()
			return sshCli, nil
		}
		if d.dialing < connections {
			break
		}
		// Every connection is being dialed by another caller: share its result.
		if d.dialed == nil {
			d.dialed = make(chan struct{})
		}
		dialed := d.dialed
		d.mut.Unlock()
		select {
		case <-dialed:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		d.mut.Lock()
	}
	d.dialing++
	closes := d.closes
	d.mut.Unlock()

	sshCli, record, err := d.dialSSHClient(ctx)

	d.mut.Lock()
	defer d.mut.Unlock()
	d.dialing--
	if d.dialed != nil {
		close(d.dialed)
		d.dialed = nil
	}
	if err != nil {
		return nil, err
	}
	if d.closes != closes {
		sshCli.Close()
		return nil, fmt.Errorf("ssh: dialer closed while connecting to %s: %w", d.host, net.ErrClosed)
	}
	d.sshCli = append(d.sshCli, pooledClient{Client: sshCli, record: record, active: new(atomic.Int64)})
	if interval := d.KeepAlive; interval > 0 {
		go d.keepAlive(sshCli, interval, record)
	}
	if len(d.sshCli) == 1 {
		d.next = 0
	}
	return sshCli, nil
}

// leastLoaded returns the index of the pooled client with the fewest open
// connections, taking equally loaded clients in turn. It requires d.mut to be
// held and the pool not to be empty.
func (d *Dialer) leastLoaded() int {
	start := d.next % len(d.sshCli)
	best := start
	for i := 1; i < len(d.sshCli); i++ {
		idx := (start + i) % len(d.sshCli)
		if d.sshCli[idx].active.Load() < d.sshCli[best].active.Load() {
			best = idx
		}
	}
	return best
}

// acquire counts a connection opened through a pooled client until the
// returned release is called. Further calls of release do nothing.
func (d *Dialer) acquire(sshCli *ssh.Client) (release func()) {
	d.mut.Lock()
	defer d.mut.Unlock()
	for i := range d.sshCli {
		if d.sshCli[i].Client == sshCli {
			active := d.sshCli[i].active
			active.Add(1)
			return sync.OnceFunc(func() { active.Add(-1) })
		}
	}
	return func() {}
}

// dialSSHClient dials and handshakes a new SSH client within the timeout.
func (d *Dialer) dialSSHClient(ctx context.Context) (*ssh.Client, *connRecord, error) {
	var deadline time.Time
	if timeout := d.config.Timeout; timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	// Live until its conn ends: a ProxyDial conn may live only as long as its ctx.
	// The conn is shared by later callers, so ctx only cancels the dial itself.
	dialCtx, cancelDial := context.WithCancel(context.WithoutCancel(ctx))

	stopLimit := atDeadline(deadline, cancelDial)
	stopCancel := context.AfterFunc(ctx, cancelDial)
	conn, err := d.proxyDial(dialCtx, "tcp", d.host)
	canceled := !stopCancel()
	if !stopLimit() {
		if err == nil {
			conn.Close()
		}
		err = d.timeoutError()
	} else if canceled {
		if err == nil {
			conn.Close()
			err = context.Cause(ctx)
		}
	}
	if err != nil {
		cancelDial()
		return nil, nil, err
	}
	record := newConnRecord(conn)
	record.onEnd = cancelDial

	stopLimit = atDeadline(deadline, func() { conn.Close() })
	con, chans, reqs, err := ssh.NewClientConn(record, d.host, d.config)
	if !stopLimit() {
		if err == nil {
			con.Close()
		}
		return nil, nil, d.timeoutError()
	}
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return ssh.NewClient(con, chans, reqs), record, nil
}

// atDeadline runs f at a non-zero deadline; stop prevents that and reports whether it did.
func atDeadline(deadline time.Time, f func()) (stop func() bool) {
	if deadline.IsZero() {
		return func() bool { return true }
	}
	return time.AfterFunc(time.Until(deadline), f).Stop
}

func (d *Dialer) timeoutError() error {
	return fmt.Errorf("ssh: connecting to %s exceeded the %v timeout: %w", d.host, d.config.Timeout, context.DeadlineExceeded)
}

func (d *Dialer) keepAlive(cli *ssh.Client, interval time.Duration, record *connRecord) {
	defer d.closeSSHClient(cli)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	var replied chan error // non-nil while a probe awaits its reply
	var arrived int64
	for {
		select {
		case <-record.done():
			return
		case err := <-replied:
			if err != nil {
				return
			}
			replied = nil
		case <-timer.C:
			n := record.arrived()
			switch {
			case record.ended():
				// SendRequest spins forever on a mux that has shut down.
				return
			case replied == nil:
				replied = make(chan error, 1)
				go func(replied chan<- error) {
					_, _, err := cli.SendRequest("keepalive@openssh.com", true, nil)
					replied <- err
				}(replied)
			case n == arrived:
				// The reply may queue behind data still arriving, so only silence closes.
				return
			}
			arrived = n
			timer.Reset(interval)
		}
	}
}

// buildCmd joins name and args into a command line for the remote shell.
// name is passed as is, so it may itself be a shell command line; every
// argument is quoted so the shell passes it on unchanged.
func buildCmd(name string, args ...string) string {
	cmds := make([]string, 0, len(args)+1)
	cmds = append(cmds, name)
	for _, arg := range args {
		cmds = append(cmds, shellQuote(arg))
	}
	return strings.Join(cmds, " ")
}

// shellQuote quotes s as a single word of a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CommandDialContext executes a command on the remote host and returns a
// net.Conn wired to its stdin/stdout. Unlike typical dialers, ctx governs
// the whole connection lifetime: canceling it kills the remote command and
// closes the connection.
func (d *Dialer) CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error) {
	cli, err := d.SSHClient(ctx)
	if err != nil {
		return nil, err
	}

	sess, err := cli.NewSession()
	if err != nil {
		return nil, err
	}

	conn1, conn2 := net.Pipe()
	sess.Stdin = conn1
	sess.Stdout = conn1
	sess.Stderr = d.Stderr
	if sess.Stderr == nil {
		sess.Stderr = os.Stderr
	}

	cmd := buildCmd(name, args...)
	err = sess.Start(cmd)
	if err != nil {
		sess.Close()
		conn1.Close()
		return nil, err
	}
	release := d.acquire(cli)
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		sess.Wait()
		cancel()
	}()
	go func() {
		<-ctx.Done()
		release()

		// openssh does not support the signal
		// command and will not signal remote processes. This may
		// be resolved in openssh 7.9 or higher. Please subscribe
		// to https://github.com/golang/go/issues/16597.
		sess.Signal(ssh.SIGKILL)
		sess.Close()
		conn1.Close()
	}()
	conn2 = connWithCloser(conn2, func() error {
		cancel()
		return nil
	})
	conn2 = connWithAddr(conn2, nil, newNetAddr("ssh-cmd", cmd))
	return conn2, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cli, err := d.SSHClient(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := cli.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	return connWithRelease(conn, d.acquire(cli)), nil
}

// Dial connects to the address from the remote host. Having no context to
// bound it, the wait for the remote host to open the connection is limited by
// the timeout of the Dialer, as is the connection to the SSH server itself.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	ctx := context.Background()
	cli, err := d.SSHClient(ctx)
	if err != nil {
		return nil, err
	}

	timeout := d.config.Timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn, err := cli.DialContext(ctx, network, address)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("ssh: dialing %s through %s exceeded the %v timeout: %w", address, d.host, timeout, err)
		}
		return nil, err
	}

	return connWithRelease(conn, d.acquire(cli)), nil
}

func (d *Dialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		if host == "" {
			address = net.JoinHostPort("0.0.0.0", port)
		}
	}

	cli, err := d.SSHClient(ctx)
	if err != nil {
		return nil, err
	}

	listener, err := cli.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return listener, nil
}
