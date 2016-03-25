package server

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/inconshreveable/go-vhost"
)

type Server struct {
	*logrus.Logger

	DefaultTLSConfig *tls.Config

	httpListener  net.Listener
	httpsListener net.Listener
	registry      map[string]*VirtualHostMatcher
	mtx           sync.RWMutex
}

func NewServer(s *Server) *Server {
	s.registry = make(map[string]*VirtualHostMatcher)
	return s
}

func (s *Server) SetHost(host string, vhm *VirtualHostMatcher) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	_, existed := s.registry[host]
	s.registry[host] = vhm
	for _, vh := range vhm.Vhosts {
		vh.ReverseProxy.SetLogWriter(s.Out)
	}
	if existed {
		s.Printf("Updated host %v", host)
	} else {
		s.Printf("Added host %v", host)
	}
}

func (s *Server) RemoveHost(host string) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if _, ok := s.registry[host]; ok {
		delete(s.registry, host)
		s.Printf("Removed host %v", host)
	}
}

func (s *Server) Listen() error {
	var err error
	s.httpListener, err = net.Listen("tcp", ":8000")
	if err != nil {
		return err
	}
	s.httpsListener, err = net.Listen("tcp", ":8443")
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) Serve() error {
	errc := make(chan error, 1)
	go s.serveHTTP(errc)
	go s.serveHTTPS(errc)
	return <-errc
}

func (s *Server) serveHTTP(errc chan error) {
	s.Printf("Serving HTTP connections on %v", s.httpListener.Addr())
	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			s.Printf("Failed to accept new HTTP connection: %v", err)
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			errc <- err
			return
		}
		httpConn, err := vhost.HTTP(conn)
		if err != nil {
			s.Printf("Invalid HTTP connection from %v", conn.RemoteAddr())
			continue
		}
		go s.handleConn(httpConn, false)
	}
}

func (s *Server) serveHTTPS(errc chan error) {
	s.Printf("Serving HTTPS connections on %v", s.httpsListener.Addr())
	for {
		conn, err := s.httpsListener.Accept()
		if err != nil {
			s.Printf("Failed to accept new HTTPS connection: %v", err)
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			errc <- err
			return
		}
		tlsConn, err := vhost.TLS(conn)
		if err != nil {
			s.Printf("Invalid TLS connection from %v", conn.RemoteAddr())
			continue
		}
		go s.handleConn(tlsConn, true)
	}
}

func (s *Server) handleConn(conn vhost.Conn, secure bool) {
	cleanup := func() {
		conn.Close()
		conn.Free()
	}
	host := conn.Host()
	if host != "" {
		if strings.Contains(host, ":") {
			host, _, _ = net.SplitHostPort(host)
		}
		host = strings.ToLower(host)
		s.Printf("Handling connection from %v on %v", conn.RemoteAddr(), host)
		vh := s.lookupHost(host)
		if vh == nil {
			cleanup()
			return
		}
		go func(conn net.Conn) {
			if secure {
				if vh.TLSConfig != nil {
					s.Printf("Setting up custom TLS termination for %v", host)
					conn = tls.Server(conn, vh.TLSConfig)
				} else if s.DefaultTLSConfig != nil {
					s.Printf("Setting up default TLS termination for %v", host)
					conn = tls.Server(conn, s.DefaultTLSConfig)
				}
			}
			backend := vh.GetStrategy().NextBackend()
			if err := vh.ReverseProxy.HandleConn(conn, backend, secure); err != nil {
				s.Printf("Error handling connection for %v: %v", host, err)
			}
			cleanup()
		}(conn)
	} else {
		cleanup()
	}
}

func (s *Server) lookupHost(host string) *VirtualHost {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	var ok bool
	var vhm *VirtualHostMatcher
	vhm, ok = s.registry[host]
	if !ok {
		d := strings.SplitN(host, ".", 2)
		for i := len(d); i > 0; i-- {
			vhm, ok = s.registry["*."+strings.Join(d[len(d)-i:], ".")]
			if ok {
				break
			}
		}
	}
	if vhm == nil {
		return nil
	}
	return vhm.Match(host)
}
