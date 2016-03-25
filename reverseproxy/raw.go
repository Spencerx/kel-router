package reverseproxy

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
)

type rawReverseProxy struct {
	logger    *logrus.Logger
	logWriter io.Writer
}

func NewRawReverseProxy() ReverseProxy {
	return &rawReverseProxy{}
}

func (rrp *rawReverseProxy) SetLogger(logger *logrus.Logger) {
	rrp.logger = logger
}

func (rrp *rawReverseProxy) SetLogWriter(w io.Writer) {
	logger := rrp.getLogger()
	logger.Out = w
}

func (rrp *rawReverseProxy) getLogger() *logrus.Logger {
	if rrp.logger == nil {
		rrp.logger = logrus.New()
		rrp.logger.Out = ioutil.Discard
	}
	return rrp.logger
}

func (rrp *rawReverseProxy) HandleConn(conn net.Conn, backend Backend, secure bool) (err error) {
	logger := rrp.getLogger()
	errLogWriter := logger.Writer()
	defer errLogWriter.Close()
	upConn, err := net.DialTimeout(
		"tcp",
		backend.Addr,
		time.Duration(backend.ConnectTimeout)*time.Millisecond,
	)
	if err != nil {
		logger.Printf("Failed to dial backend connection %v: %v", backend.Addr, err)
		return
	}
	rrp.logger.Printf("Initiated new connection to backend: %v %v", upConn.LocalAddr(), upConn.RemoteAddr())
	joinConnections(conn, upConn, log.New(errLogWriter, "", 0))
	return
}
