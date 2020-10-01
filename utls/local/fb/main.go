package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	tls "github.com/hunterbdm/hello-requests/utls"
	"golang.org/x/net/http2"
)

// (ipv6.src == 2600:1405:e000::/64 or ipv6.dst==2600:1405:e000::/64)
// (ipv6.src == 2600:1405:e000::/64 or ipv6.dst==2600:1405:e000::/64) && (ssl.handshake.type==1 or ssl.handshake.type==2)

var dialTimeout = time.Duration(30) * time.Second

// var requestHostname = "www.yeezysupply.com"
// var requestAddr = "[2600:1405:e000::1730:b80]:443"

var requestHostname = "www.facebook.com"
var requestAddr = "[2a03:2880:f141:82:face:b00c:0:25de]:443"

func main() {
	var err error
	var config = &tls.Config{
		// ClientSessionCache is required to store PSK identities sent by the
		//		server to be used in consecutive connections.
		ClientSessionCache:     tls.NewLRUClientSessionCache(32),
		SessionTicketsDisabled: false,
		MaxVersion:             tls.VersionTLS13,
		ServerName:             requestHostname,
	}

	err = testConnection(config, false)
	if err != nil {
		fmt.Printf("failed initial test: %+v\n", err)
		os.Exit(1)
	}

	// Create new connection and reconnect -- config is local so ClientSessionCache stores
	//		any PSK identities sent by the server during the initial connection.
	err = testConnection(config, true)
	if err != nil {
		fmt.Printf("failed resumption test: %+v\n", err)
		os.Exit(1)
	}
}

func testConnection(config *tls.Config, shouldResume bool) error {
	var response *http.Response
	var err error

	// Create a TLS connection over the TCP conn that uses the most recently generated
	// 	  Chrome clientHello fingerprint.
	conn, err := establishUTLSConn(config, tls.HelloChrome_Auto)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Check if the connection used PSK resumption by examining the connectionState.
	clientState := conn.ConnectionState()
	if clientState.DidResume != shouldResume {
		// fmt.Println("Connected using PSK session resumption")
		return fmt.Errorf("\"shouldResume\" did not match \"ConnectionState.DidResume\"")
	}

	// Get Page and return results.
	response, err = httpGetOverConn(conn, conn.HandshakeState.ServerHello.AlpnProtocol)
	defer func() {
		// cleanup connection after completion
		if response != nil {
			response.Body.Close()
		}
		conn.Close()
	}()

	if err != nil {
		return fmt.Errorf("http request failed: %+v", err)
	}

	fmt.Printf("#> response:\n%+s\n", dumpResponseNoBody(response))

	return nil
}

func establishUTLSConn(config *tls.Config, fingerprint tls.ClientHelloID) (*tls.UConn, error) {

	// Establish TCP Connection
	dialConn, err := net.DialTimeout("tcp", requestAddr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}

	// Establish the TLS connection.
	conn := tls.UClient(dialConn, config, fingerprint)
	err = conn.Handshake()
	if err != nil {
		dialConn.Close()
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return conn, nil
}

func httpGetOverConn(conn net.Conn, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: requestHostname + "/"},
		Header: make(http.Header),
		Host:   requestHostname,
	}

	req.Header.Add("authority", "www.yeezysupply.com")
	req.Header.Add("cache-control", "max-age=0")
	req.Header.Add("dnt", "1")
	req.Header.Add("upgrade-insecure-requests", "1")
	req.Header.Add("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36")
	req.Header.Add("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("sec-fetch-site", "same-origin")
	req.Header.Add("sec-fetch-mode", "navigate")
	req.Header.Add("sec-fetch-user", "?1")
	req.Header.Add("sec-fetch-dest", "document")
	req.Header.Add("accept-language", "en-US,en;q=0.9")

	// req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36")

	alpn = "h2"
	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(os.Stdout)
		if err != nil {
			return nil, err
		}

		err = req.Write(conn)
		if err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(time.Duration(10) * time.Second))

		buf, err := ioutil.ReadAll(conn)
		fmt.Printf("#> Received %d:\n%+v\n%s\n", len(buf), buf, buf)

		if err != nil {
			return nil, fmt.Errorf("failed to call cli.Read: %v", err)
		}

		fmt.Printf("HERE\n")
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func dumpResponseNoBody(response *http.Response) string {
	resp, err := httputil.DumpResponse(response, false)
	if err != nil {
		return fmt.Sprintf("failed to dump response: %v", err)
	}
	return string(resp)
}
