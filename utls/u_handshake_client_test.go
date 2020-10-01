package tls

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
)

func TestUTLSResumption(t *testing.T) {
	// t.Run("TLSv12", func(t *testing.T) { testUTLSResumption(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testUTLSResumption(t, VersionTLS13) })
}

func testUTLSResumption(t *testing.T, version uint16) {

	serverConfig := &Config{
		MaxVersion:   version,
		CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305},
		Certificates: testConfig.Certificates,
	}

	issuer, err := x509.ParseCertificate(testRSACertificateIssuer)
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	clientConfig := &Config{
		MaxVersion:             version,
		CipherSuites:           []uint16{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305},
		ClientSessionCache:     NewLRUClientSessionCache(32),
		RootCAs:                rootCAs,
		ServerName:             "example.golang",
		SessionTicketsDisabled: false,
	}

	testResumeState := func(test string, didResume bool) {
		_, hs, err := testUTLSHandshake(t, clientConfig, serverConfig)
		if err != nil {
			t.Fatalf("%s: handshake failed: %s", test, err)
		}
		if hs.DidResume != didResume {
			t.Fatalf("%s resumed: %v, expected: %v", test, hs.DidResume, didResume)
		}
		if didResume && (hs.PeerCertificates == nil || hs.VerifiedChains == nil) {
			t.Fatalf("expected non-nil certificates after resumption. Got peerCertificates: %#v, verifiedCertificates: %#v", hs.PeerCertificates, hs.VerifiedChains)
		}
	}

	getTicket := func() []byte {
		return clientConfig.ClientSessionCache.(*lruSessionCache).q.Front().Value.(*lruSessionCacheEntry).state.sessionTicket
	}
	deleteTicket := func() {
		ticketKey := clientConfig.ClientSessionCache.(*lruSessionCache).q.Front().Value.(*lruSessionCacheEntry).sessionKey
		clientConfig.ClientSessionCache.Put(ticketKey, nil)
	}
	corruptTicket := func() {
		clientConfig.ClientSessionCache.(*lruSessionCache).q.Front().Value.(*lruSessionCacheEntry).state.masterSecret[0] ^= 0xff
	}
	randomKey := func() [32]byte {
		var k [32]byte
		if _, err := io.ReadFull(serverConfig.rand(), k[:]); err != nil {
			t.Fatalf("Failed to read new SessionTicketKey: %s", err)
		}
		return k
	}

	testResumeState("Handshake", false)

	ticket := getTicket()

	testResumeState("Resume", true)

	if !bytes.Equal(ticket, getTicket()) && version != VersionTLS13 {
		t.Fatal("first ticket doesn't match ticket after resumption")
	}
	if bytes.Equal(ticket, getTicket()) && version == VersionTLS13 {
		t.Fatal("ticket didn't change after resumption")
	}

	key1 := randomKey()
	serverConfig.SetSessionTicketKeys([][32]byte{key1})

	testResumeState("InvalidSessionTicketKey", false)
	testResumeState("ResumeAfterInvalidSessionTicketKey", true)

	key2 := randomKey()
	serverConfig.SetSessionTicketKeys([][32]byte{key2, key1})
	ticket = getTicket()
	testResumeState("KeyChange", true)
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("new ticket wasn't included while resuming")
	}
	testResumeState("KeyChangeFinish", true)

	// Reset serverConfig to ensure that calling SetSessionTicketKeys
	// before the serverConfig is used works.
	serverConfig = &Config{
		MaxVersion:   version,
		CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		Certificates: testConfig.Certificates,
	}
	serverConfig.SetSessionTicketKeys([][32]byte{key2})

	testResumeState("FreshConfig", true)

	// In TLS 1.3, cross-cipher suite resumption is allowed as long as the KDF
	// hash matches. Also, Config.CipherSuites does not apply to TLS 1.3.
	if version != VersionTLS13 {
		clientConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_RC4_128_SHA}
		testResumeState("DifferentCipherSuite", false)
		testResumeState("DifferentCipherSuiteRecovers", true)
	}

	deleteTicket()
	testResumeState("WithoutSessionTicket", false)

	// Session resumption should work when using client certificates
	deleteTicket()
	serverConfig.ClientCAs = rootCAs
	serverConfig.ClientAuth = RequireAndVerifyClientCert
	clientConfig.Certificates = serverConfig.Certificates
	testResumeState("InitialHandshake", false)
	testResumeState("WithClientCertificates", true)
	serverConfig.ClientAuth = NoClientCert

	// Tickets should be removed from the session cache on TLS handshake
	// failure, and the client should recover from a corrupted PSK
	testResumeState("FetchTicketToCorrupt", false)
	corruptTicket()
	_, _, err = testUTLSHandshake(t, clientConfig, serverConfig)
	if err == nil {
		t.Fatalf("handshake did not fail with a corrupted client secret")
	}
	testResumeState("AfterHandshakeFailure", false)

	clientConfig.ClientSessionCache = nil
	testResumeState("WithoutSessionCache", false)
}

func testUTLSHandshake(t *testing.T, clientConfig, serverConfig *Config) (serverState, clientState ConnectionState, err error) {

	testRequest := "GET / HTTP/1.1\r\n\r\n"

	c, s := localPipe(t)
	errChan := make(chan error)
	go func() {
		cli := UClient(c, clientConfig, HelloChrome_Auto)
		err := cli.Handshake()
		if err != nil {
			errChan <- fmt.Errorf("client: %v", err)
			c.Close()
			return
		}
		defer cli.Close()
		clientState = cli.ConnectionState()
		if _, err := io.WriteString(cli, testRequest); err != nil {
			t.Errorf("failed to call client.Write: %v", err)
		}

		buf, err := ioutil.ReadAll(cli)

		if err != nil {
			t.Errorf("failed to call cli.Read: %v", err)
		}
		if got := string(buf); got != opensslSentinel {
			t.Errorf("client read %q from TLS connection, but expected %q", got, opensslSentinel)
		}
		errChan <- nil
	}()
	server := Server(s, serverConfig)
	err = server.Handshake()
	if err != nil {
		s.Close()
		<-errChan
		return
	}

	serverState = server.ConnectionState()

	buf := make([]byte, len(testRequest))
	_, err = io.ReadFull(server, buf)
	if err != nil {
		t.Errorf("server ReadFull error: %+v", err)
	}

	if got := string(buf); got != testRequest {
		t.Errorf("server read %q from TLS connection, but expected %q", got, testRequest)
	}

	if _, err := io.WriteString(server, opensslSentinel); err != nil {
		t.Errorf("failed to call server.Write: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Errorf("failed to call server.Close: %v", err)
	}
	err = <-errChan

	return
}
