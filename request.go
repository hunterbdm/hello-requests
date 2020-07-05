package request

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"sync"

	"github.com/hunterbdm/hello-requests/http"

	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/hunterbdm/hello-requests/http/cookiejar"

	utls "github.com/refraction-networking/utls"
)

var (
	// CHROME is the 'key' for the Google Chrome(< 83) clientHelloSpec
	CHROME = "Chrome"
	// CHROMEH1 is the 'key' for the Google Chrome(< 83) clientHelloSpec using only http1
	CHROMEH1 = "Chrome_HTTP1"
	// CHROME83 is the 'key' for the Google Chrome(>= 83) clientHelloSpec
	CHROME83 = "Chrome83"
	// CHROME83H1 is the 'key' for the Google Chrome(>= 83) clientHelloSpec using only http1
	CHROME83H1 = "Chrome83_HTTP1"
	// FIREFOX is the 'key' for the Firefox clientHelloSpec
	FIREFOX = "Firefox"
	// IPHONEX is the 'key' for the iPhone X clientHelloSpec
	IPHONEX = "iPhoneX"
	// IPHONE11 is the 'key' for the iPhone 11 clientHelloSpec
	IPHONE11 = "iPhone11"

	debugLogging    = false
	skipVerifyCerts = false
	clientMap       = map[string]*http.Client{}
	clientMapMutex  = sync.RWMutex{}
)

// Headers is a [string]string map of http header values
type Headers map[string]string

// HeaderOrder is a string array for the order of http headers
type HeaderOrder []string

// Options defines the options used to initiate a request
type Options struct {
	ID           string // Optional id to track requests
	Method       string
	URL          string
	Headers      Headers
	HeaderOrder  []string
	Body         string
	Proxy        string
	MimicBrowser string
	Jar          *cookiejar.Jar
	Timeout      int
	FollowRedirects bool
}

// Response defines the results of a request
type Response struct {
	ID         string
	Error      string
	StatusCode int
	Headers    map[string][]string
	Body       string
	Time       int
}

func newClient(rawProxy, mimicBrowser string, timeout int, followRedirects bool) (*http.Client, error) {
	if mimicBrowser == "" {
		mimicBrowser = CHROME
	}

	var tp http.Transport
	if rawProxy != "" {
		proxySplit := strings.Split(rawProxy, ":")
		var proxyURI *url.URL
		var err error

		if len(proxySplit) == 2 { // ip:port
			proxyURI, err = url.Parse("http://" + rawProxy)
		} else if len(proxySplit) == 4 { // ip:port:user:pass
			proxyURI, err = url.Parse("http://" + proxySplit[2] + ":" + proxySplit[3] + "@" + proxySplit[0] + ":" + proxySplit[1])
		}

		if err != nil {
			return nil, err
		}

		tp = http.Transport{
			Proxy: http.ProxyURL(proxyURI),
			MimicBrowser: mimicBrowser,
			GetHelloSpec: getHelloSpec,
			IdleConnTimeout: 5 * time.Second,
		}
	} else {
		tp = http.Transport{
			MimicBrowser: mimicBrowser,
			GetHelloSpec: getHelloSpec,
			IdleConnTimeout: 5 * time.Second,
		}
	}

	client := http.Client{
		Timeout:       time.Duration(timeout) * time.Millisecond,
		Transport: &tp,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &client, nil
}

func getClient(proxy, mimicBrowser string, timeout int, followRedirects bool) (*http.Client, error) {
	identifier := proxy + "_" + mimicBrowser + "_" + strconv.Itoa(timeout) + "_" + strconv.FormatBool(followRedirects)

	// Use previously stored client if found
	clientMapMutex.RLock()
	savedClient, ok := clientMap[identifier]
	clientMapMutex.RUnlock()
	if ok {
		return savedClient, nil
	}

	client, err := newClient(proxy, mimicBrowser, timeout, followRedirects)
	if err != nil {
		return nil, err
	}
	// Store client in map
	clientMapMutex.Lock()
	clientMap[identifier] = client
	clientMapMutex.Unlock()

	return client, nil
}

func getHelloSpec(specName string) *utls.ClientHelloSpec {
	switch specName {
	case CHROME: // Google Chrome (version:81.0.4044.138) (os:windows10) (ja3 hash:66918128f1b9b03303d77c6f2eefd128)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.CurveID(utls.GREASE_PLACEHOLDER),
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
					}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					utls.PKCS1WithSHA1,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: utls.X25519},
					}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
				&utls.FakeCertCompressionAlgsExtension{
					Methods: []utls.CertCompressionAlgo{
						utls.CertCompressionBrotli,
					}},
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	case CHROMEH1: // Google Chrome (version:81.0.4044.138) (os:windows10) (ja3 hash:66918128f1b9b03303d77c6f2eefd128) (http1 only)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.CurveID(utls.GREASE_PLACEHOLDER),
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
					}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					utls.PKCS1WithSHA1,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: utls.X25519},
					}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
				&utls.FakeCertCompressionAlgsExtension{
					Methods: []utls.CertCompressionAlgo{
						utls.CertCompressionBrotli,
					}},
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	case CHROME83: // Google Chrome (version:83.0.4103.61) (os:windows10) (ja3 hash:b32309a26951912be7dba376398abc3b)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.CurveID(utls.GREASE_PLACEHOLDER),
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
					}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					//utls.PKCS1WithSHA1,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: utls.X25519},
					}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
				&utls.FakeCertCompressionAlgsExtension{
					Methods: []utls.CertCompressionAlgo{
						utls.CertCompressionBrotli,
					}},
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	case CHROME83H1: // Google Chrome (version:83.0.4103.61) (os:windows10) (ja3 hash:b32309a26951912be7dba376398abc3b) (http1 only)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.CurveID(utls.GREASE_PLACEHOLDER),
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
					}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					//utls.PKCS1WithSHA1,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: utls.X25519},
					}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
				&utls.FakeCertCompressionAlgsExtension{
					Methods: []utls.CertCompressionAlgo{
						utls.CertCompressionBrotli,
					}},
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	case FIREFOX: // Firefox (version:74.0) (os:windows10) (ja3 hash:aa7744226c695c0b2e440419848cf700)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
						utls.CurveP521,
						utls.CurveID(256),
						utls.CurveID(257),
					}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.X25519},
						{Group: utls.CurveP256},
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.VersionTLS13,
						utls.VersionTLS12,
					}},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
					utls.ECDSAWithSHA1,
					utls.PKCS1WithSHA1,
				}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			// TLSVersMax: utls.VersionTLS13,
			// TLSVersMin: utls.VersionTLS10,
		}
	case IPHONEX: // iPhone X (ios:12.4) (ja3 hash:7a7a639628f0fe5c7e057628a5bbec5a) (tested apps:chrome/safari)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				0xC008, //utls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					utls.PKCS1WithSHA1,
				}},
				&utls.StatusRequestExtension{},
				&utls.NPNExtension{},
				&utls.SCTExtension{},
				&utls.ALPNExtension{
					AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"},
				},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: utls.X25519},
					}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
						utls.CurveP521,
					}},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	case IPHONE11: // iPhone 11 (ios:13.3) (ja3 hash:6fa3244afc6bb6f9fad207b6b52af26b) (tested apps:chrome/safari)
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				0xC008, //utls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					utls.PKCS1WithSHA1,
				}},
				&utls.StatusRequestExtension{},
				//&utls.NPNExtension{},
				&utls.SCTExtension{},
				&utls.ALPNExtension{
					AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"},
				},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: utls.X25519},
					}},
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
				&utls.SupportedCurvesExtension{
					Curves: []utls.CurveID{
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
						utls.CurveP521,
					}},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	default:
		return getHelloSpec(CHROME)
	}
}

func decompressBody(data []byte, encoding string) string {
	var w bytes.Buffer

	if encoding == "gzip" {
		gr, _ := gzip.NewReader(bytes.NewBuffer(data))
		defer gr.Close()
		data, _ = ioutil.ReadAll(gr)
		w.Write(data)

		return w.String()
	}
	// Add others later if needed

	return string(data)
}

// Jar returns an empty http cookie jar
func Jar() *cookiejar.Jar {
	jar, _ := cookiejar.New(nil)
	return jar
}

// Do creates a new request and returns the response
func Do(opts Options) (*Response, error) {
	resp, err := request(opts)
	return resp, err
}

// DisableCertChecks disables extra certificate verification (for dev testing mode)
func DisableCertChecks() {
	skipVerifyCerts = true
}

// EnableDebugLogging turns on debug logging
func EnableDebugLogging() {
	debugLogging = true
}

// request does the full process of managing a client and processing the http/https request
func request(opts Options) (*Response, error) {
	// Validate request options
	if opts.URL == "" {
		return &Response{ID: opts.ID, Error: errors.New("missing parameter URL").Error()}, errors.New("missing parameter URL")
	}
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 60000
	}

	// Parse URL to get hostname
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return &Response{ID: opts.ID, Error: err.Error()}, err
	}

	// Set cookie header
	if opts.Jar != nil {
		cookiesForRequest := opts.Jar.Cookies(parsedURL)

		if len(cookiesForRequest) > 0 {
			cookieHeader := ""

			for _, cookie := range cookiesForRequest {
				cookieHeader += cookie.String() + "; "
			}

			opts.Headers["Cookie"] = cookieHeader
		}
	}

	// Build http.Request
	req, err := http.NewRequest(opts.Method, opts.URL, strings.NewReader(opts.Body))
	if err != nil {
		return &Response{ID: opts.ID, Error: err.Error()}, err
	}

	if len(opts.HeaderOrder) > 0 {
		for _, hName := range opts.HeaderOrder {
			nameFixed := textproto.CanonicalMIMEHeaderKey(hName)
			req.HeaderOrder = append(req.HeaderOrder, nameFixed)
		}
	}
	for name, value := range opts.Headers {
		req.Header.Set(name, value)
	}

	// Find client from history or create new one
	hostHeader := req.Header.Get("Host")
	client, err := getClient(opts.Proxy, opts.MimicBrowser, opts.Timeout, opts.FollowRedirects)

	if err != nil {
		return &Response{ID: opts.ID, Error: err.Error()}, err
	}

	if len(hostHeader) > 0 {
		req.Host = hostHeader
	}

	// Set MimicBrowser on the request object so it can be referenced when settings http2 headers
	if opts.MimicBrowser != "" {
		req.MimicBrowser = opts.MimicBrowser
	} else {
		req.MimicBrowser = CHROME
	}

	startTime := time.Now().UnixNano() / int64(time.Millisecond)
	if debugLogging {
		fmt.Println("[hello-requests] Starting request: ", opts.ID)
	}
	resp, err := client.Do(req)
	if debugLogging {
		fmt.Println("[hello-requests] Request finished: ", opts.ID)
	}
	endTime := time.Now().UnixNano() / int64(time.Millisecond)

	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return &Response{ID: opts.ID, Error: err.Error()}, err
	}

	var body string
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &Response{ID: opts.ID, Error: err.Error()}, err
	}
	// Decompress body if needed
	if vals, ok := resp.Header["Content-Encoding"]; ok {
		body = decompressBody(bodyBytes, vals[0])
	} else {
		body = string(bodyBytes)
	}

	// Set response cookies in jar
	if opts.Jar != nil {
		opts.Jar.SetCookies(parsedURL, http.ReadSetCookies(resp.Header))
	}

	return &Response{
		ID:         opts.ID,
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Time:       int(endTime - startTime),
	}, nil
}
