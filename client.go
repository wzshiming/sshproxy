package sshproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

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
	return d, nil
}

func NewDialerWithConfig(host string, config *ssh.ClientConfig) (*Dialer, error) {
	return &Dialer{
		host:        host,
		config:      config,
		Connections: 1,
	}, nil
}

type clientConfig struct {
	host         string
	clientConfig *ssh.ClientConfig
	connections  int
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
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if isPwd {
		config.Auth = append(config.Auth, ssh.Password(pwd))
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
		if err != nil {
			return nil, err
		}
	}

	config.Timeout = timeout

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
	}, nil
}

type Dialer struct {
	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
	// Connections is the maximum number of SSH transport connections maintained.
	// Values less than or equal to 0 are treated as 1.
	Connections int

	host   string
	config *ssh.ClientConfig

	mut    sync.Mutex
	sshCli []*ssh.Client
	next   int
}

func (d *Dialer) Close() error {
	d.mut.Lock()
	defer d.mut.Unlock()
	if len(d.sshCli) == 0 {
		return nil
	}

	var firstErr error
	for _, sshCli := range d.sshCli {
		if sshCli == nil {
			continue
		}
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
		if d.sshCli[i] != sshCli {
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

func (d *Dialer) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := d.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}

func (d *Dialer) SSHClient(ctx context.Context) (*ssh.Client, error) {
	d.mut.Lock()
	defer d.mut.Unlock()

	connections := d.connections()

	if len(d.sshCli) > 0 && len(d.sshCli) >= connections {
		idx := d.next % len(d.sshCli)
		d.next = (d.next + 1) % len(d.sshCli)
		return d.sshCli[idx], nil
	}

	conn, err := d.proxyDial(ctx, "tcp", d.host)
	if err != nil {
		return nil, err
	}

	con, chans, reqs, err := ssh.NewClientConn(conn, d.host, d.config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	sshCli := ssh.NewClient(con, chans, reqs)
	d.sshCli = append(d.sshCli, sshCli)
	if len(d.sshCli) == 1 {
		d.next = 0
	}
	return sshCli, nil
}

func buildCmd(name string, args ...string) string {
	cmds := make([]string, 0, len(args)+1)
	cmds = append(cmds, name)
	for _, arg := range args {
		cmds = append(cmds, strconv.Quote(arg))
	}
	return strings.Join(cmds, " ")
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
		d.closeSSHClient(cli)
		return nil, err
	}

	conn1, conn2 := net.Pipe()
	sess.Stdin = conn1
	sess.Stdout = conn1
	sess.Stderr = os.Stderr

	cmd := buildCmd(name, args...)
	err = sess.Start(cmd)
	if err != nil {
		sess.Close()
		conn1.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		sess.Wait()
		cancel()
	}()
	go func() {
		<-ctx.Done()

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
		d.closeSSHClient(cli)
		return nil, err
	}

	return conn, nil
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	cli, err := d.SSHClient(context.Background())
	if err != nil {
		return nil, err
	}

	conn, err := cli.Dial(network, address)
	if err != nil {
		d.closeSSHClient(cli)
		return nil, err
	}

	return conn, nil
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
		d.closeSSHClient(cli)
		return nil, err
	}

	return listener, nil
}
