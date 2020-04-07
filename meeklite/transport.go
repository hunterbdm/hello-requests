package meeklite

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/hunterbdm/hello-requests/http"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hunterbdm/hello-requests/http2"

	utls "github.com/refraction-networking/utls"
)

var (
	errProtocolNegotiated = errors.New("protocol negotiated")
)

// DialFunc is used a Dial function
type DialFunc func(string, string) (net.Conn, error)

// roundTripper is the round tripper
type roundTripper struct {
	sync.Mutex

	clientHelloSpec *utls.ClientHelloSpec
	dialFn          DialFunc
	transport       http.RoundTripper

	initConn net.Conn
}

// RTClient stores and manages the roundTripper
type RTClient struct {
	rt            roundTripper
	LastRequestTS int64 // UNIX timestamp to make sure we dont reuse client after connection has done bad
}

// Do forwards the req to the RoundTripper
func (rtc *RTClient) Do(req *http.Request) (*http.Response, error) {
	resp, err := rtc.rt.RoundTrip(req)
	rtc.LastRequestTS = time.Now().UnixNano() / int64(time.Millisecond)
	return resp, err
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Note: This isn't protected with a lock, since the meeklite ioWorker
	// serializes RoundTripper requests.
	//
	// This also assumes that req.URL.Host will remain constant for the
	// lifetime of the roundTripper, which is a valid assumption for meeklite.
	if rt.transport == nil {
		if err := rt.getTransport(req); err != nil {
			return nil, err
		}
	}
	return rt.transport.RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.transport = newHTTPTransport(rt.dialFn, nil)
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: '%v'", req.URL.Scheme)
	}

	_, err := rt.dialTLS("tcp", getDialTLSAddr(req.URL))
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("dialTLS returned no error when determining transport")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(network, addr string) (net.Conn, error) {
	// Unlike rt.transport, this is protected by a critical section
	// since past the initial manual call from getTransport, the HTTP
	// client will be the caller.
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// transport to use, return that.
	if conn := rt.initConn; conn != nil {
		rt.initConn = nil
		return conn, nil
	}

	rawConn, err := rt.dialFn(network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	var verifyPeerCertificateFn func([][]byte, [][]*x509.Certificate) error

	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:                  host,
		VerifyPeerCertificate:       verifyPeerCertificateFn,
		DynamicRecordSizingDisabled: true,
	}, utls.HelloCustom)

	if err := conn.ApplyPreset(rt.clientHelloSpec); err != nil {
		return nil, err
	}
	if err = conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	if rt.transport != nil {
		return conn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN.
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// The remote peer is speaking HTTP 2 + TLS.
		t2 := &http2.Transport{DialTLS: rt.dialTLSHTTP2}

		// Custom function in our http2.Transport so you can
		// apply settings when directly creating http2.Transport
		t2.SetT1(&http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       35 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		})

		rt.transport = t2
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		rt.transport = newHTTPTransport(nil, rt.dialTLS)
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.initConn = conn

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return rt.dialTLS(network, addr)
}

func newHTTPTransport(dialFn, dialTLSFn DialFunc) *http.Transport {
	base := (http.DefaultTransport).(*http.Transport)

	return &http.Transport{
		Dial:    dialFn,
		DialTLS: dialTLSFn,

		// Use default configuration values, taken from the runtime.
		MaxIdleConns:          base.MaxIdleConns,
		IdleConnTimeout:       35 * time.Second,
		TLSHandshakeTimeout:   base.TLSHandshakeTimeout,
		ExpectContinueTimeout: base.ExpectContinueTimeout,
	}
}

func getDialTLSAddr(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	pInt, _ := net.LookupPort("tcp", u.Scheme)

	return net.JoinHostPort(u.Host, strconv.Itoa(pInt))
}

// NewRTC creates a RTClient with a roundTripper
func NewRTC(dialFn DialFunc, clientHelloSpec *utls.ClientHelloSpec) *RTClient {
	return &RTClient{
		rt: roundTripper{
			dialFn:          dialFn,
			clientHelloSpec: clientHelloSpec,
		},
	}
}
