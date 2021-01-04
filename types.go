package request

import (
	"encoding/json"
	"errors"
	"github.com/hunterbdm/hello-requests/http/cookiejar"
	"net/textproto"
	"net/url"
	"strings"
)

type Headers map[string]string

type HeaderOrder []string

type JSON map[string]interface{}

type Options struct {
	Method         string
	URL            string
	Headers        Headers
	HeaderOrder    HeaderOrder
	Body           string
	Json           JSON
	Jar            *cookiejar.Jar
	ClientSettings *ClientSettings

	// true if we should attempt to JSON parse the response, no matter the response "Content-Type" header
	ParseJSONResponse bool
}

type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
	Json       JSON
	Request    *Options
	Time       int
}

func (o *Options) Validate() (*url.URL, error) {
	// Fix Method
	if o.Method == "" {
		o.Method = "GET"
	} else {
		o.Method = strings.ToUpper(o.Method)
	}

	// Make sure Headers map is not nil
	if o.Headers == nil {
		o.Headers = Headers{}
	}

	// Format all headers in HeaderOrder
	for i, header := range o.HeaderOrder {
		o.HeaderOrder[i] = textproto.CanonicalMIMEHeaderKey(header)
	}

	// Stringify JSON body if provided
	if o.Json != nil {
		if o.Body != "" {
			return nil, errors.New("cannot provide both 'Body' and 'Json'")
		}

		jsonBody, err := json.Marshal(o.Json)

		if err != nil {
			return nil, errors.New("invalid JSON body")
		}

		o.Body = string(jsonBody)
	}

	// Validate URL
	parsedUrl, err := url.Parse(o.URL)
	if err != nil {
		return nil, errors.New("invalid URL")
	}

	return parsedUrl, nil
}