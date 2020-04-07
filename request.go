package request

import (
	"bytes"
	"compress/gzip"
	"errors"
	"github.com/hunterbdm/hello-requests/http"
	"github.com/hunterbdm/hello-requests/meeklite"
	"io/ioutil"

	"github.com/hunterbdm/hello-requests/http/cookiejar"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var (
	// CHROME is the 'key' for the Google Chrome clientHelloSpec
	CHROME = "Chrome"
	// FIREFOX is the 'key' for the Firefox clientHelloSpec
	FIREFOX = "Firefox"
	// IPHONEX is the 'key' for the iPhone X clientHelloSpec
	IPHONEX = "iPhoneX"
	// IPHONE11 is the 'key' for the iPhone 11 clientHelloSpec
	IPHONE11 = "iPhone11"

	clientMap = map[string]*meeklite.RTClient{}
)

type Headers map[string]string
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
}

// Response defines the results of a request
type Response struct {
	Error      error
	StatusCode int
	Headers    map[string][]string
	Body       string
	Time       int
}

func newClient(rawProxy, mimicBrowser string) (*meeklite.RTClient, error) {
	if mimicBrowser == "" {
		mimicBrowser = CHROME
	}

	clientHelloSpec := getHelloSpec(mimicBrowser)

	dialFn := proxy.Direct.Dial
	if rawProxy != "" {
		proxySplit := strings.Split(rawProxy, ":")
		var proxyURI *url.URL
		var err error

		if len(proxySplit) == 2 { // ip:port
			proxyURI, err = url.Parse("http://" + rawProxy)
		} else if len(proxySplit) == 4 { // ip:port:user:pass
			proxyURI, err = url.Parse("http://" + proxySplit[0] + ":" + proxySplit[1])
		}

		dialer, err := proxy.FromURL(proxyURI, proxy.Direct)
		if err != nil {
			return nil, err
		}
		dialFn = dialer.Dial
	}

	rtc := meeklite.NewRTC(dialFn, &clientHelloSpec)

	return rtc, nil
}

func getClient(hostname, proxy, mimicBrowser string) (*meeklite.RTClient, error) {
	identifier := hostname + "_" + proxy + "_" + mimicBrowser
	now := time.Now().UnixNano() / int64(time.Millisecond)

	// Use previously stored client if found
	if savedClient, ok := clientMap[identifier]; ok && now-savedClient.LastRequestTS < 34000 {
		return savedClient, nil
	}

	client, err := newClient(proxy, mimicBrowser)
	if err != nil {
		return nil, err
	}
	// Store client in map
	clientMap[identifier] = client
	return client, nil
}

func getHelloSpec(specName string) utls.ClientHelloSpec {
	switch specName {
	case CHROME: // Google Chrome (version:80.0.3987.163) (os:windows10) (ja3 hash:66918128f1b9b03303d77c6f2eefd128)
		return utls.ClientHelloSpec{
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
						//{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
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
	case FIREFOX: // Firefox (version:74.0) (os:windows10) (ja3 hash:b20b44b18b853ef29ab773e921b03422)
		return utls.ClientHelloSpec{
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
				0x0033, //utls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				0x0039, //utls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
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
					}},
				&utls.SupportedVersionsExtension{
					Versions: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.VersionTLS13,
						utls.VersionTLS12,
						utls.VersionTLS11,
						utls.VersionTLS10,
					}},
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
				&utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						utls.PskModeDHE,
					}},
				&utls.FakeRecordSizeLimitExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
			TLSVersMax: utls.VersionTLS13,
			TLSVersMin: utls.VersionTLS10,
		}
	case IPHONEX: // iPhone X (ios:12.4) (ja3 hash:7a7a639628f0fe5c7e057628a5bbec5a) (tested apps:chrome/safari)
		return utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				0xC024, //utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				0xC028, //utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				0x003D, //utls.TLS_RSA_WITH_AES_256_CBC_SHA256,
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
		return utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				0xC024, //utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				0xC028, //utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				0x003D, //utls.TLS_RSA_WITH_AES_256_CBC_SHA256,
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

// Request does the full process of managing a client and processing the http/https request
func request(opts Options) (*Response, error) {
	// Validate request options
	if opts.URL == "" {
		return &Response{Error: errors.New("missing parameter URL")}, errors.New("missing parameter URL")
	}
	if opts.Method == "" {
		opts.Method = "GET"
	}

	// Parse URL to get hostname
	parsedURL, err := url.Parse(opts.URL)
	// Find client from history or create new one
	client, err := getClient(parsedURL.Hostname(), opts.Proxy, opts.MimicBrowser)
	if err != nil {
		return &Response{Error: err}, err
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
	req, _ := http.NewRequest(opts.Method, opts.URL, strings.NewReader(opts.Body))
	if len(opts.HeaderOrder) > 0 {
		for _, hName := range opts.HeaderOrder {
			nameFixed := textproto.CanonicalMIMEHeaderKey(hName)
			req.HeaderOrder = append(req.HeaderOrder, nameFixed)
		}
	}
	for name, value := range opts.Headers {
		req.Header.Set(name, value)
	}

	startTime := time.Now().UnixNano() / int64(time.Millisecond)
	resp, err := client.Do(req)
	endTime := time.Now().UnixNano() / int64(time.Millisecond)

	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return &Response{Error: err}, err
	}

	var body string
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &Response{Error: err}, err
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
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Time:       int(endTime - startTime),
	}, nil
}
