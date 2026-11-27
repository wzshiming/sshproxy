package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wzshiming/sshd"
	"github.com/wzshiming/sshproxy/permissions"
	"golang.org/x/crypto/ssh"
)

// SimpleServer is a simplified server, which can be configured as easily as client.
type SimpleServer struct {
	Server
	Listener net.Listener
	Username string
	Password string
	Network  string
	Address  string

	mut    sync.Mutex
	conns  map[net.Conn]struct{} // accepted and not yet closed
	closed bool
}

// NewSimpleServer creates a new NewSimpleServer
func NewSimpleServer(addr string) (*SimpleServer, error) {
	user, pwd, host, config, userPermissions, err := serverConfig(addr)
	if err != nil {
		return nil, err
	}

	s := &SimpleServer{
		Server: Server{
			ServerConfig:    *config,
			UserPermissions: userPermissions,
		},
		Network:  "tcp",
		Address:  host,
		Username: user,
		Password: pwd,
	}
	return s, nil
}

func serverConfig(addr string) (user, pwd, host string, config *ssh.ServerConfig, userPermissions func(user string) sshd.Permissions, err error) {
	ur, err := url.Parse(addr)
	if err != nil {
		return "", "", "", nil, nil, err
	}

	isPwd := false
	if ur.User != nil {
		user = ur.User.Username()
		pwd, isPwd = ur.User.Password()
	}

	config = &ssh.ServerConfig{}

	if isPwd {
		user := user
		pwd := pwd
		config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == user && string(password) == pwd {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		}
	} else {
		user = ""
		pwd = ""
	}

	hostkeyDatas, err := getQuery(ur.Query()["hostkey_data"], ur.Query()["hostkey_file"])
	if err != nil {
		return "", "", "", nil, nil, err
	}
	if len(hostkeyDatas) == 0 {
		key, err := sshd.RandomHostkey()
		if err != nil {
			return "", "", "", nil, nil, err
		}
		config.AddHostKey(key)
	} else {
		for _, data := range hostkeyDatas {
			key, err := sshd.ParseHostkey(data)
			if err != nil {
				return "", "", "", nil, nil, err
			}
			config.AddHostKey(key)
		}
	}

	pks := []func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error){}
	authorizedDatas, err := getQuery(ur.Query()["authorized_data"], ur.Query()["authorized_file"])
	if err != nil {
		return "", "", "", nil, nil, err
	}
	if len(authorizedDatas) != 0 {
		keys, err := sshd.ParseAuthorized(bytes.NewBuffer(bytes.Join(authorizedDatas, []byte{'\n'})))
		if err != nil {
			return "", "", "", nil, nil, err
		}
		if len(keys.Data) != 0 {
			pks = append(pks, func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				ok, _ := keys.Allow(key)
				if ok {
					return nil, nil
				}
				return nil, fmt.Errorf("denied")
			})
		}
	}

	homeDirs := ur.Query()["home_dir"]
	if len(homeDirs) != 0 && homeDirs[0] != "" {
		homeDir := homeDirs[0]
		sshDirName := ".ssh"
		sshDirNames := ur.Query()["ssh_dir_name"]
		if len(sshDirNames) != 0 {
			sshDirName = sshDirNames[0]
		}
		authorizedFileName := "authorized_keys"
		authorizedFileNames := ur.Query()["authorized_file_name"]
		if len(authorizedFileNames) != 0 {
			authorizedFileName = authorizedFileNames[0]
		}
		pks = append(pks, func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			file, ok := userFile(homeDir, conn.User(), sshDirName, authorizedFileName)
			if !ok {
				return nil, fmt.Errorf("denied")
			}
			keys, err := sshd.GetAuthorizedFile(file)
			if err != nil {
				return nil, fmt.Errorf("denied")
			}
			ok, _ = keys.Allow(key)
			if ok {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		})

		// Other sshd implementations do not have such fine-grained permissions control,
		// and this is a fine-grained set of permissions control files defined by the project itself
		permissionsFileName := ""
		permissionsFileNames := ur.Query()["permissions_file_name"]
		if len(permissionsFileNames) != 0 {
			permissionsFileName = permissionsFileNames[0]
		}
		if permissionsFileName != "" {
			permissionsFileUpdatePeriod := time.Duration(0)
			permissionsFileUpdatePeriods := ur.Query()["permissions_file_update_period"]
			if len(permissionsFileUpdatePeriods) != 0 {
				permissionsFileUpdatePeriod, _ = time.ParseDuration(permissionsFileUpdatePeriods[0])
			}
			userPermissions = func(user string) sshd.Permissions {
				file, ok := userFile(homeDir, user, sshDirName, permissionsFileName)
				if !ok {
					return permissions.Permissions{}
				}
				return permissions.NewPermissionsFromFile(file, permissionsFileUpdatePeriod)
			}
		}
	}

	if len(pks) != 0 {
		if len(pks) == 1 {
			config.PublicKeyCallback = pks[0]
		} else {
			config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (p *ssh.Permissions, err error) {
				for _, pk := range pks {
					p, err = pk(conn, key)
					if err == nil {
						break
					}
				}
				return
			}
		}
	}

	// must have be authenticated or not, default is false
	authenticate, _ := strconv.ParseBool(ur.Query().Get("authenticate"))
	if !authenticate && config.PasswordCallback == nil && config.PublicKeyCallback == nil && config.KeyboardInteractiveCallback == nil {
		config.NoClientAuth = true
	}

	host = ur.Hostname()
	port := ur.Port()
	if port == "" {
		port = "22"
	}
	host = net.JoinHostPort(host, port)
	return user, pwd, host, config, userPermissions, nil
}

// userFile returns the path of the named file in the ssh directory of user
// under homeDir. It reports false for a user name that is not a single path
// element, which would otherwise select a directory outside homeDir.
func userFile(homeDir, user, sshDirName, name string) (string, bool) {
	if user == "" || user == "." || user == ".." || strings.ContainsAny(user, "/\\\x00") {
		return "", false
	}
	return filepath.Join(homeDir, user, sshDirName, name), true
}

// Run listens and serves until ctx ends or the server is closed. When ctx
// ends it closes the server, connections included, and returns the cause.
func (s *SimpleServer) Run(ctx context.Context) error {
	listener, err := s.listen(ctx)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	err = s.Serve(listener)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}

// Start listens and serves in the background until the server is closed.
// ctx only bounds the listening; the server keeps running after it ends.
func (s *SimpleServer) Start(ctx context.Context) error {
	listener, err := s.listen(ctx)
	if err != nil {
		return err
	}
	go s.Serve(listener)
	return nil
}

// listen opens the Listener unless one was provided, and returns it wrapped to
// keep track of the connections it accepts.
func (s *SimpleServer) listen(ctx context.Context) (net.Listener, error) {
	if s.Listener == nil {
		var listenConfig net.ListenConfig
		listener, err := listenConfig.Listen(ctx, s.Network, s.Address)
		if err != nil {
			return nil, err
		}
		s.Listener = listener
	}
	if address := s.Listener.Addr().String(); s.Address != address {
		s.Address = address
	}
	return &trackedListener{Listener: s.Listener, server: s}, nil
}

// Close closes the listener and every connection accepted through it.
func (s *SimpleServer) Close() error {
	s.mut.Lock()
	s.closed = true
	conns := s.conns
	s.conns = nil
	s.mut.Unlock()
	for conn := range conns {
		conn.Close()
	}
	if s.Listener == nil {
		return nil
	}
	return s.Listener.Close()
}

// track records an accepted connection, or reports false once the server is closed.
func (s *SimpleServer) track(conn net.Conn) bool {
	s.mut.Lock()
	defer s.mut.Unlock()
	if s.closed {
		return false
	}
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *SimpleServer) untrack(conn net.Conn) {
	s.mut.Lock()
	defer s.mut.Unlock()
	delete(s.conns, conn)
}

// trackedListener records the connections it accepts with its server.
type trackedListener struct {
	net.Listener
	server *SimpleServer
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &trackedConn{Conn: conn, server: l.server}
	if !l.server.track(tracked) {
		conn.Close()
		return nil, net.ErrClosed
	}
	return tracked, nil
}

type trackedConn struct {
	net.Conn
	server *SimpleServer
}

func (c *trackedConn) Close() error {
	c.server.untrack(c)
	return c.Conn.Close()
}

// ProxyURL returns the URL of the proxy
func (s *SimpleServer) ProxyURL() string {
	u := url.URL{
		Scheme: "ssh",
		Host:   s.Address,
	}
	if s.Username != "" {
		u.User = url.UserPassword(s.Username, s.Password)
	}
	return u.String()
}
