package sshproxy

import (
	"github.com/wzshiming/sshd"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/tcpforward"
)

type Server = sshd.Server
