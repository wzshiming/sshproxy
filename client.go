package sshproxy

import (
	"context"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// NewDialer returns a new Dialer that dials through the provided
// proxy server's network and address.
func NewDialer(addr string) (*Dialer, error) {
	host, config, err := clientConfig(addr)
	if err != nil {
		return nil, err
	}
	return NewDialerWithConfig(host, config)
}

func NewDialerWithConfig(host string, config *ssh.ClientConfig) (*Dialer, error) {
	return &Dialer{
		host:   host,
		config: config,
	}, nil
}

func clientConfig(addr string) (host string, config *ssh.ClientConfig, err error) {
	ur, err := url.Parse(addr)
	if err != nil {
		return "", nil, err
	}

	user := ""
	pwd := ""
	isPwd := false
	if ur.User != nil {
		user = ur.User.Username()
		pwd, isPwd = ur.User.Password()
	}

	config = &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if isPwd {
		config.Auth = append(config.Auth, ssh.Password(pwd))
	}

	identityFiles := ur.Query()["identity_file"]
	for _, ident := range identityFiles {
		if ident == "" {
			continue
		}
		if strings.HasPrefix(ident, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				ident = filepath.Join(home, ident[1:])
			}
		}

		file, err := ioutil.ReadFile(ident)
		if err != nil {
			return "", nil, err
		}
		signer, err := ssh.ParsePrivateKey(file)
		if err != nil {
			return "", nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	host = ur.Hostname()
	port := ur.Port()
	if port == "" {
		port = "22"
	}
	host = net.JoinHostPort(host, port)
	return host, config, nil
}

type Dialer struct {
	mut       sync.Mutex
	localAddr net.Addr
	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
	sshCli    *ssh.Client
	host      string
	config    *ssh.ClientConfig
}

func (d *Dialer) Close() error {
	d.mut.Lock()
	defer d.mut.Unlock()
	if d.sshCli == nil {
		return nil
	}
	err := d.sshCli.Close()
	d.sshCli = nil
	return err
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
	cli := d.sshCli
	if cli != nil {
		return cli, nil
	}
	conn, err := d.proxyDial(ctx, "tcp", d.host)
	if err != nil {
		return nil, err
	}

	con, chans, reqs, err := ssh.NewClientConn(conn, d.host, d.config)
	if err != nil {
		return nil, err
	}
	cli = ssh.NewClient(con, chans, reqs)
	d.sshCli = cli
	return cli, nil
}

func (d *Dialer) CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error) {
	cmd := make([]string, 0, len(args)+1)
	cmd = append(cmd, name)
	for _, arg := range args {
		cmd = append(cmd, strconv.Quote(arg))
	}
	return d.commandDialContext(ctx, strings.Join(cmd, " "), 1)
}

func (d *Dialer) commandDialContext(ctx context.Context, cmd string, retry int) (net.Conn, error) {
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
	sess.Stderr = os.Stderr
	err = sess.Start(cmd)
	if err != nil {
		if retry != 0 {
			d.Close()
			return d.commandDialContext(ctx, cmd, retry-1)
		}
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
	conn2 = connWithAddr(conn2, d.localAddr, newNetAddr("ssh-cmd", cmd))
	return conn2, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialContext(ctx, network, address, 1)
}

func (d *Dialer) dialContext(ctx context.Context, network, address string, retry int) (net.Conn, error) {
	cli, err := d.SSHClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := cli.Dial(network, address)
	if err != nil {
		if retry != 0 {
			d.Close()
			return d.dialContext(ctx, network, address, retry-1)
		}
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
	return d.listen(ctx, network, address, 1)
}

func (d *Dialer) listen(ctx context.Context, network, address string, retry int) (net.Listener, error) {
	cli, err := d.SSHClient(ctx)
	if err != nil {
		return nil, err
	}
	listener, err := cli.Listen(network, address)
	if err != nil {
		if retry != 0 {
			d.Close()
			return d.listen(ctx, network, address, retry-1)
		}
		return nil, err
	}
	return listener, nil
}
