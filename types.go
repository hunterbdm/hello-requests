package request

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hunterbdm/hello-requests/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
)

type Headers map[string]string

type HeaderOrder []string

type JSON map[string]interface{}

type Options struct {
	Method      string `json:"Method"`
	URL         string `json:"URL"`
	Headers     Headers `json:"Headers"`
	HeaderOrder HeaderOrder `json:"HeaderOrder"`
	Body        string `json:"Body"`
	Json        JSON `json:"Json"`
	Form        JSON `json:"Form"`
	QS          JSON `json:"QS"`
	Base64Body  bool `json:"Base64Body"`

	Jar            *cookiejar.Jar
	ClientSettings *ClientSettings `json:"ClientSettings"`

	FollowRedirects bool `json:"FollowRedirects"`

	// true if we should attempt to JSON parse the response, no matter the response "Content-Type" header
	ParseJSONResponse bool `json:"ParseJSONResponse"`
}

type Response struct {
	StatusCode int `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       string `json:"Body"`
	Json       JSON `json:"Json"`
	Request    *Options `json:"Request"`
	Previous   *Response `json:"Previous"`
	Time       int `json:"Time"`
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
	//for i, header := range o.HeaderOrder {
	//	o.HeaderOrder[i] = textproto.CanonicalMIMEHeaderKey(header)
	//}


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
	} else if o.Form != nil {
		if o.Body != "" {
			return nil, errors.New("cannot provide both 'Body' and 'Form'")
		}

		o.Body = o.Form.QSMarshal()
	}

	// Validate URL
	parsedUrl, err := url.Parse(o.URL)
	if err != nil {
		return nil, errors.New("invalid URL")
	}

	// Add raw query string body to url
	if o.QS != nil {
		parsedUrl.RawQuery = o.QS.QSMarshal()
		o.URL = parsedUrl.String()
	}

	return parsedUrl, nil
}

func (form *JSON) QSMarshal() string {
	values := url.Values{}

	for name, val := range *form {
		if valFloat64, ok := val.(float64); ok {
			values.Add(name, fmt.Sprintf("%g", valFloat64))
		} else if valInt, ok := val.(int); ok {
			values.Add(name, strconv.Itoa(valInt))
		} else {
			values.Add(name, val.(string))
		}
	}

	return values.Encode()
}