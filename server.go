package sshproxy

import (
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/tcpforward"

	"github.com/wzshiming/sshd"
)

type Server = sshd.Server

var NewServer = sshd.NewServer
