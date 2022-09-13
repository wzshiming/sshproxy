package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
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

func serverConfig(addr string) (host, user, pwd string, config *ssh.ServerConfig, userPermissions func(user string) sshd.Permissions, err error) {
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
			file := path.Join(homeDir, conn.User(), sshDirName, authorizedFileName)
			keys, err := sshd.GetAuthorizedFile(file)
			if err != nil {
				return nil, fmt.Errorf("denied")
			}
			ok, _ := keys.Allow(key)
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
				file := path.Join(homeDir, user, sshDirName, permissionsFileName)
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
