package reverseproxy

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
)

type httpReverseProxy struct {
	transport http.RoundTripper
	logger    *logrus.Logger
	logWriter io.Writer
}

func NewHTTPReverseProxy() ReverseProxy {
	return &httpReverseProxy{
		transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

func (rrp *httpReverseProxy) SetLogger(logger *logrus.Logger) {
	rrp.logger = logger
}

func (rrp *httpReverseProxy) SetLogWriter(w io.Writer) {
	logger := rrp.getLogger()
	logger.Out = w
}

func (rrp *httpReverseProxy) getLogger() *logrus.Logger {
	if rrp.logger == nil {
		rrp.logger = logrus.New()
		rrp.logger.Out = ioutil.Discard
	}
	return rrp.logger
}

func (rrp *httpReverseProxy) HandleConn(conn net.Conn, backend Backend, secure bool) error {
	logger := rrp.getLogger()
	errLogWriter := logger.Writer()
	defer errLogWriter.Close()
	target, _ := url.Parse(fmt.Sprintf("http://%s", backend.Addr))
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	rp := &httpReverseProxyHandler{
		Director:  director,
		ErrorLog:  log.New(errLogWriter, "", 0),
		Transport: rrp.transport,
	}
	var handler http.Handler
	if secure {
		handler = fwdProtoHandler{
			Handler: rp,
			Proto:   "https",
			Port:    "443",
		}
	} else {
		handler = fwdProtoHandler{
			Handler: rp,
			Proto:   "http",
			Port:    "80",
		}
	}
	done := make(chan struct{}, 1)
	handler = syncHandler{Handler: handler, done: done}
	srv := &http.Server{
		Handler:  handler,
		ErrorLog: log.New(errLogWriter, "", 0),
	}
	if err := srv.Serve(&singleConnListener{conn: conn}); err != nil {
		if err.Error() != "listener done" {
			return err
		}
	}
	<-done
	return nil
}

type singleConnListener struct {
	conn     net.Conn
	returned bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.returned {
		return nil, errors.New("listener done")
	}
	l.returned = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return nil
}

// onExitFlushLoop is a callback set by tests to detect the state of the
// flushLoop() goroutine.
var onExitFlushLoop func()

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
type httpReverseProxyHandler struct {
	// Director must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	Director func(*http.Request)

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// ErrorLog specifies an optional logger for errors
	// that occur when attempting to proxy the request.
	// If nil, logging goes to os.Stderr via the log package's
	// standard logger.
	ErrorLog *log.Logger

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool BufferPool
}

// A BufferPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
}

type requestCanceler interface {
	CancelRequest(*http.Request)
}

type runOnFirstRead struct {
	io.Reader // optional; nil means empty body

	fn func() // Run before first Read, then set to nil
}

func (c *runOnFirstRead) Read(bs []byte) (int, error) {
	if c.fn != nil {
		c.fn()
		c.fn = nil
	}
	if c.Reader == nil {
		return 0, io.EOF
	}
	return c.Reader.Read(bs)
}

func (p *httpReverseProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay

	p.Director(outreq)
	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	// Remove hop-by-hop headers to the backend. This
	// is modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}
	if !req.ProtoAtLeast(1, 1) || !isConnectionUpgrade(req.Header) {
		outreq.Header.Del("Upgrade")
		// Especially important is "Connection" because we want a persistent
		// connection, regardless of what the client sent to us.
		outreq.Header.Del("Connection")
		// A proxy or gateway MUST parse a received Connection header field before a
		// message is forwarded and, for each connection-option in this field, remove
		// any header field(s) from the message with the same name as the
		// connection-option, and then remove the Connection header field itself (or
		// replace it with the intermediary's own connection options for the
		// forwarded message): https://tools.ietf.org/html/rfc7230#section-6.1
		tokens := strings.Split(req.Header.Get("Connection"), ",")
		for _, hdr := range tokens {
			outreq.Header.Del(hdr)
		}
		if closeNotifier, ok := rw.(http.CloseNotifier); ok {
			if requestCanceler, ok := transport.(requestCanceler); ok {
				reqDone := make(chan struct{})
				defer close(reqDone)

				clientGone := closeNotifier.CloseNotify()

				outreq.Body = struct {
					io.Reader
					io.Closer
				}{
					Reader: &runOnFirstRead{
						Reader: outreq.Body,
						fn: func() {
							go func() {
								select {
								case <-clientGone:
									requestCanceler.CancelRequest(outreq)
								case <-reqDone:
								}
							}()
						},
					},
					Closer: outreq.Body,
				}
			}
		}
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}

	if res.StatusCode == http.StatusSwitchingProtocols {
		res.Body.Close()
		hj, ok := rw.(http.Hijacker)
		if !ok {
			p.logf("http: proxy error: %v", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			p.logf("http: proxy error: %v", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		backendConn, err := net.Dial("tcp", outreq.URL.Host)
		if err != nil {
			p.logf("http: proxy error: %v", err)
			return
		}
		defer backendConn.Close()
		outreq.Write(backendConn)
		joinConnections(conn, backendConn, p.ErrorLog)
	} else {
		for _, h := range hopHeaders {
			res.Header.Del(h)
		}
		copyHeader(rw.Header(), res.Header)
		// The "Trailer" header isn't included in the Transport's response,
		// at least for *http.Transport. Build it up from Trailer.
		if len(res.Trailer) > 0 {
			var trailerKeys []string
			for k := range res.Trailer {
				trailerKeys = append(trailerKeys, k)
			}
			rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
		}
		rw.WriteHeader(res.StatusCode)
		if len(res.Trailer) > 0 {
			// Force chunking if we saw a response trailer.
			// This prevents net/http from calculating the length for short
			// bodies and adding a Content-Length.
			if fl, ok := rw.(http.Flusher); ok {
				fl.Flush()
			}
		}
		p.copyResponse(rw, res.Body)
		res.Body.Close() // close now, instead of defer, to populate res.Trailer
		copyHeader(rw.Header(), res.Trailer)
	}
}

func (p *httpReverseProxyHandler) copyResponse(dst io.Writer, src io.Reader) {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	var buf []byte
	if p.BufferPool != nil {
		buf = p.BufferPool.Get()
	}
	io.CopyBuffer(dst, src, buf)
	if p.BufferPool != nil {
		p.BufferPool.Put(buf)
	}
}

func (p *httpReverseProxyHandler) logf(format string, args ...interface{}) {
	if p.ErrorLog != nil {
		p.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	lk   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.lk.Lock()
	defer m.lk.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.lk.Lock()
			m.dst.Flush()
			m.lk.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }

const (
	fwdForHeaderName   = "X-Forwarded-For"
	fwdProtoHeaderName = "X-Forwarded-Proto"
	fwdPortHeaderName  = "X-Forwarded-Port"
)

// fwdProtoHandler is an http.Handler that sets the X-Forwarded-For header on
// inbound requests to match the remote IP address, and sets X-Forwarded-Proto
// and X-Forwarded-Port headers to match the values in Proto and Port. If those
// headers already exist, the new values will be appended.
type fwdProtoHandler struct {
	http.Handler
	Proto string
	Port  string
}

func (h fwdProtoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If we aren't the first proxy retain prior X-Forwarded-* information as a
	// comma+space separated list and fold multiple headers into one.
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior, ok := r.Header[fwdForHeaderName]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		r.Header.Set(fwdForHeaderName, clientIP)
	}

	proto, port := h.Proto, h.Port
	if prior, ok := r.Header[fwdProtoHeaderName]; ok {
		proto = strings.Join(prior, ", ") + ", " + proto
	}
	if prior, ok := r.Header[fwdPortHeaderName]; ok {
		port = strings.Join(prior, ", ") + ", " + port
	}
	r.Header.Set(fwdProtoHeaderName, proto)
	r.Header.Set(fwdPortHeaderName, port)

	h.Handler.ServeHTTP(w, r)
}

type syncHandler struct {
	http.Handler
	done chan struct{}
}

func (h syncHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Handler.ServeHTTP(w, r)
	h.done <- struct{}{}
}

func isConnectionUpgrade(h http.Header) bool {
	for _, token := range strings.Split(h.Get("Connection"), ",") {
		if v := strings.ToLower(strings.TrimSpace(token)); v == "upgrade" {
			return true
		}
	}
	return false
}
