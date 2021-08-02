package request

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/hunterbdm/hello-requests/compress"
	"github.com/hunterbdm/hello-requests/http"
	"github.com/hunterbdm/hello-requests/http/cookiejar"
	"github.com/hunterbdm/hello-requests/utils"
	"io/ioutil"
	"strings"
	"time"
)

// Features:
//
// - Matching ClientHello fingerprints (done)
// - Matching http/2 fingerprints (done)
// - Matching http/2 header order (done)
// - Custom normal header ordering (done)
// - Trusted certificate checks (done)
// - JSON response parsing (done)
// - JSON body building (done)
// - Custom idle connection timeouts (done)
// - Custom request timeouts (done)
// - Brotli decompression (done)

// utls additions/fixes:
//
// - PreSharedKey extension support added
// - Fixed the same value being used on both GREASE extensions
//   causing "tls: error decoding message"

// TODO
//
// - Add PSK toggle

func Do(opts Options) (*Response, error) {
	return request(opts, nil)
}

func Jar() *cookiejar.Jar {
	jar, _ := cookiejar.New(nil)
	return jar
}

func base64Decode(message []byte) (b []byte, err error) {
	var l int
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, err = base64.StdEncoding.Decode(b, message)
	if err != nil {
		return
	}
	return b[:l], nil
}

func request(opts Options, previous *Response) (*Response, error) {
	if opts.ClientSettings == nil {
		opts.ClientSettings = &defaultClientSettings
	} else {
		opts.ClientSettings.AddDefaults()
	}

	// Check for errors in options provided
	parsedUrl, err := opts.Validate()
	if err != nil {
		return nil, err
	}

	// Add cookie header from Jar
	if opts.Jar != nil {
		cookieHeader := ""

		for i, cookie := range opts.Jar.Cookies(parsedUrl) {
			if i > 0 {
				cookieHeader += " "
			}
			cookieHeader += cookie.String() + ";"
		}

		if cookieHeader != "" {
			opts.Headers["Cookie"] = cookieHeader
		}
	} else {
		opts.Jar = Jar()
	}

	// Build http.Request to pass into the http.Client
	var req *http.Request
	if opts.Base64Body {
		byteBody, err := base64Decode([]byte(opts.Body))
		if err != nil {
			return nil, errors.New("bad base64 body")
		}

		req, err = http.NewRequest(opts.Method, opts.URL, bytes.NewReader(byteBody))
	} else {
		req, err = http.NewRequest(opts.Method, opts.URL, strings.NewReader(opts.Body))
	}
	if err != nil {
		return nil, err
	}

	for name, value := range opts.Headers {
		//req.Header[name] = []string{value}
		req.Header.Set(name, value)
	}
	// Add HeaderOrder onto request to be used later in the h2_bundle
	req.HeaderOrder = opts.HeaderOrder

	if req.Header.Get("Host") != "" {
		req.Host = req.Header.Get("Host")

		if req.Host != parsedUrl.Host {
			opts.ClientSettings.CustomServerName = req.Header.Get("Host")
		}
	}

	// Pull http.Client with ClientSettings options
	httpClient := GetHttpClient(opts.ClientSettings)

	start := time.Now().UnixNano() / int64(time.Millisecond)
	resp, err := httpClient.Do(req)
	end := time.Now().UnixNano() / int64(time.Millisecond)

	if err != nil {
		return nil, err
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	var body string
	if bodyBytes, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	} else {
		end = time.Now().UnixNano() / int64(time.Millisecond)

		if encoding, ok := resp.Header["Content-Encoding"]; ok {
			body = compress.Decompress(bodyBytes, encoding[0])
		} else {
			body = string(bodyBytes)
		}
	}

	// Add response cookies to jar
	opts.Jar.SetCookies(parsedUrl, utils.ReadSetCookies(resp.Header))

	var jsonParsed JSON
	if opts.ParseJSONResponse {
		_ = json.Unmarshal([]byte(body), &jsonParsed)
	} else if contentType, ok := resp.Header["Content-Type"]; ok && strings.Contains(contentType[0], "application/json") {
		// Attempt to parse JSON body if response content-type is "application/json"
		_ = json.Unmarshal([]byte(body), &jsonParsed)
	}

	res := Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Json:       jsonParsed,
		Request:    &opts,
		Time:       int(end - start),
		Previous: 	previous,
	}

	// Return redirected response if we are following redirects
	loc, ok := res.Headers["Location"]
	if opts.FollowRedirects && ok && len(loc) > 0 {
		newHeaders := opts.Headers
		delete(newHeaders, "content-length")
		delete(newHeaders, "Content-Length")
		delete(newHeaders, "origin")
		delete(newHeaders, "Origin")
		delete(newHeaders, "content-type")
		delete(newHeaders, "Content-Type")
		delete(newHeaders, "host")
		delete(newHeaders, "Host")


		url := loc[0]
		// Check if the baseUrl is included in the location header
		if strings.Index(url, "/") == 0 {
			url = parsedUrl.Scheme + "://" + parsedUrl.Host + url
		}

		newOpts := Options{
			URL: url,
			Headers: newHeaders,
			HeaderOrder: opts.HeaderOrder,
			Jar: opts.Jar,
			ClientSettings: opts.ClientSettings,
			FollowRedirects: opts.FollowRedirects,
			ParseJSONResponse: opts.ParseJSONResponse,
		}

		return request(newOpts, &res)
	}

	return &res, nil
}