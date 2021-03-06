package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/wzshiming/sshd"
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
}

// NewSimpleServer creates a new NewSimpleServer
func NewSimpleServer(addr string) (*SimpleServer, error) {
	user, pwd, host, config, err := serverConfig(addr)
	if err != nil {
		return nil, err
	}

	s := &SimpleServer{
		Server: Server{
			ServerConfig: *config,
		},
		Network:  "tcp",
		Address:  host,
		Username: user,
		Password: pwd,
	}
	return s, nil
}

func serverConfig(addr string) (host, user, pwd string, config *ssh.ServerConfig, err error) {
	ur, err := url.Parse(addr)
	if err != nil {
		return "", "", "", nil, err
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
		return "", "", "", nil, err
	}
	if len(hostkeyDatas) == 0 {
		key, err := sshd.RandomHostkey()
		if err != nil {
			return "", "", "", nil, err
		}
		config.AddHostKey(key)
	} else {
		for _, data := range hostkeyDatas {
			key, err := sshd.ParseHostkey(data)
			if err != nil {
				return "", "", "", nil, err
			}
			config.AddHostKey(key)
		}
	}

	authorizedDatas, err := getQuery(ur.Query()["authorized_data"], ur.Query()["authorized_file"])
	if err != nil {
		return "", "", "", nil, err
	}
	allKeys := map[string]string{}
	for _, data := range authorizedDatas {
		keys, err := sshd.ParseAuthorized(bytes.NewBuffer(data))
		if err != nil {
			return "", "", "", nil, err
		}
		for k, v := range keys {
			allKeys[k] = v
		}
	}
	if len(allKeys) != 0 {
		config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			k := string(key.Marshal())
			if _, ok := allKeys[k]; ok {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
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
	return user, pwd, host, config, nil
}

// Run the server
func (s *SimpleServer) Run(ctx context.Context) error {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, s.Network, s.Address)
	if err != nil {
		return err
	}
	s.Listener = listener
	s.Address = listener.Addr().String()
	return s.Serve(listener)
}

// Start the server
func (s *SimpleServer) Start(ctx context.Context) error {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, s.Network, s.Address)
	if err != nil {
		return err
	}
	s.Listener = listener
	s.Address = listener.Addr().String()
	go s.Serve(listener)
	return nil
}

// Close closes the listener
func (s *SimpleServer) Close() error {
	if s.Listener == nil {
		return nil
	}
	return s.Listener.Close()
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
