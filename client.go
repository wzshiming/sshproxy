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

func (c *Dialer) reset() {
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.sshCli == nil {
		return
	}
	c.sshCli.Close()
	c.sshCli = nil
}

func (d *Dialer) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := d.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}

func (c *Dialer) getCli(ctx context.Context) (*ssh.Client, error) {
	c.mut.Lock()
	defer c.mut.Unlock()
	cli := c.sshCli
	if cli != nil {
		return cli, nil
	}
	conn, err := c.proxyDial(ctx, "tcp", c.host)
	if err != nil {
		return nil, err
	}

	con, chans, reqs, err := ssh.NewClientConn(conn, c.host, c.config)
	if err != nil {
		return nil, err
	}
	cli = ssh.NewClient(con, chans, reqs)
	c.sshCli = cli
	return cli, nil
}

func (c *Dialer) CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error) {
	cmd := make([]string, 0, len(args)+1)
	cmd = append(cmd, name)
	for _, arg := range args {
		cmd = append(cmd, strconv.Quote(arg))
	}
	return c.commandDialContext(ctx, strings.Join(cmd, " "), 1)
}

func (c *Dialer) commandDialContext(ctx context.Context, cmd string, retry int) (net.Conn, error) {
	cli, err := c.getCli(ctx)
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
			c.reset()
			return c.commandDialContext(ctx, cmd, retry-1)
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
	conn2 = connWithAddr(conn2, c.localAddr, newNetAddr("ssh-cmd", cmd))
	return conn2, nil
}

func (c *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.dialContext(ctx, network, address, 1)
}

func (c *Dialer) dialContext(ctx context.Context, network, address string, retry int) (net.Conn, error) {
	cli, err := c.getCli(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := cli.Dial(network, address)
	if err != nil {
		if retry != 0 {
			c.reset()
			return c.dialContext(ctx, network, address, retry-1)
		}
		return nil, err
	}
	return conn, nil
}

func (c *Dialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		address = net.JoinHostPort("0.0.0.0", port)
	}
	return c.listen(ctx, network, address, 1)
}

func (c *Dialer) listen(ctx context.Context, network, address string, retry int) (net.Listener, error) {
	cli, err := c.getCli(ctx)
	if err != nil {
		return nil, err
	}
	listener, err := cli.Listen(network, address)
	if err != nil {
		if retry != 0 {
			c.reset()
			return c.listen(ctx, network, address, retry-1)
		}
		return nil, err
	}
	return listener, nil
}
