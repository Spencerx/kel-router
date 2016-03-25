package reverseproxy

import (
	"io"
	"net"

	"github.com/Sirupsen/logrus"
)

type Backend struct {
	Addr           string
	ConnectTimeout int
}

type ReverseProxy interface {
	SetLogger(*logrus.Logger)
	SetLogWriter(io.Writer)
	HandleConn(net.Conn, Backend, bool) error
}
