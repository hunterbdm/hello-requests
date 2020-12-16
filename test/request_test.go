package test

import (
	request "github.com/hunterbdm/hello-requests"
	"strconv"
	"testing"
)

// go test ./test -v

func TestGoogle(t *testing.T) {
	for i := 0; i < 5; i++ {
		_, err := request.Do(request.Options{
			Method: "GET",
			URL: "https://www.google.com/",
			Headers: request.Headers{
				"upgrade-insecure-requests": "1",
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
				"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"sec-fetch-site": "none",
				"sec-fetch-mode": "navigate",
				"sec-fetch-user": "?1",
				"sec-fetch-dest": "document",
				"accept-encoding": "gzip, deflate, br",
				"accept-language": "en-US,en;q=0.9",
			},
			HeaderOrder: request.HeaderOrder{
				"upgrade-insecure-requests",
				"user-agent",
				"accept",
				"content-length",
				"sec-fetch-site",
				"sec-fetch-mode",
				"sec-fetch-user",
				"sec-fetch-dest",
				"accept-encoding",
				"accept-language",
				"cookie",
			},
			ClientSettings: &request.ClientSettings{
				IdleTimeoutTime: 5000 + i,
			},
		})

		if err != nil {
			t.Error(err)
			return
		}
	}
}

func TestShopify(t *testing.T) {
	for i := 0; i < 5; i++ {
		_, err := request.Do(request.Options{
			Method: "GET",
			URL: "https://kith.com/products.json?limit=1",
			Headers: request.Headers{
				"upgrade-insecure-requests": "1",
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
				"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"sec-fetch-site": "none",
				"sec-fetch-mode": "navigate",
				"sec-fetch-user": "?1",
				"sec-fetch-dest": "document",
				"accept-encoding": "gzip, deflate, br",
				"accept-language": "en-US,en;q=0.9",
			},
			HeaderOrder: request.HeaderOrder{
				"upgrade-insecure-requests",
				"user-agent",
				"accept",
				"content-length",
				"sec-fetch-site",
				"sec-fetch-mode",
				"sec-fetch-user",
				"sec-fetch-dest",
				"accept-encoding",
				"accept-language",
				"cookie",
			},
			ClientSettings: &request.ClientSettings{
				IdleTimeoutTime: 5000 + i,
			},
		})

		if err != nil {
			t.Error(err)
			return
		}
	}
}

func TestYS(t *testing.T) {
	for i := 0; i < 5; i++ {
		_, err := request.Do(request.Options{
			Method: "GET",
			URL: "https://www.yeezysupply.com/",
			Headers: request.Headers{
				"upgrade-insecure-requests": "1",
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
				"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"sec-fetch-site": "none",
				"sec-fetch-mode": "navigate",
				"sec-fetch-user": "?1",
				"sec-fetch-dest": "document",
				"accept-encoding": "gzip, deflate, br",
				"accept-language": "en-US,en;q=0.9",
			},
			HeaderOrder: request.HeaderOrder{
				"upgrade-insecure-requests",
				"user-agent",
				"accept",
				"content-length",
				"sec-fetch-site",
				"sec-fetch-mode",
				"sec-fetch-user",
				"sec-fetch-dest",
				"accept-encoding",
				"accept-language",
				"cookie",
			},
			ClientSettings: &request.ClientSettings{
				IdleTimeoutTime: 5000 + i,
			},
		})

		if err != nil {
			t.Error(err)
			return
		}
	}
}

func TestChromeFP(t *testing.T) {
	resp, err := request.Do(request.Options{
		URL: "https://fp.dashe.ai/rc?bypass=encryption",
		ParseJSONResponse: true,
		ClientSettings: &request.ClientSettings{
			MimicBrowser: "chrome",
			SkipCertChecks: true,
		},
	})

	if err != nil {
		t.Error(err)
		return
	} else if resp.StatusCode != 200 {
		t.Error("bad response " + strconv.Itoa(resp.StatusCode))
		return
	} else if resp.Json == nil {
		t.Error("No json body parsed")
		return
	}

	if resp.Json["ja3Hash"].(string) != "b32309a26951912be7dba376398abc3b" {
		t.Error("bad tls fingerprint: " + resp.Json["ja3Hash"].(string))
		return
	}

	if resp.Json["h2Hash"].(string) != "8a32ff5cb625ed4ae2d092e76beb6d99" {
		t.Error("bad h2 fingerprint: " + resp.Json["ja3Hash"].(string))
		return
	}
}

func TestFirefoxFP(t *testing.T) {
	resp, err := request.Do(request.Options{
		URL: "https://fp.dashe.ai/rc?bypass=encryption",
		ParseJSONResponse: true,
		ClientSettings: &request.ClientSettings{
			MimicBrowser: "firefox",
			SkipCertChecks: true,
		},
	})

	if err != nil {
		t.Error(err)
		return
	} else if resp.StatusCode != 200 {
		t.Error("bad response " + strconv.Itoa(resp.StatusCode))
		return
	} else if resp.Json == nil {
		t.Error("No json body parsed")
		return
	}

	if resp.Json["ja3Hash"].(string) != "f2a9f94284e5d331627ccacf0511219b" {
		t.Error("bad tls fingerprint: " + resp.Json["ja3Hash"].(string))
		return
	}

	if resp.Json["h2Hash"].(string) != "3d9132023bf26a71d40fe766e5c24c9d" {
		t.Log(resp.Json["h2Fingerprint"])
		t.Error("bad h2 fingerprint: " + resp.Json["ja3Hash"].(string))
		return
	}
}

func TestBrotli(t *testing.T) {
	resp, err := request.Do(request.Options{
		Method: "GET",
		URL: "https://kith.com/products.json?limit=1",
		Headers: request.Headers{
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site": "none",
			"sec-fetch-mode": "navigate",
			"sec-fetch-user": "?1",
			"sec-fetch-dest": "document",
			"accept-encoding": "br",
			"accept-language": "en-US,en;q=0.9",
		},
		HeaderOrder: request.HeaderOrder{
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"content-length",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"cookie",
		},
	})

	if err != nil {
		t.Error(err)
		return
	} else if resp.StatusCode != 200 {
		t.Error("bad response " + strconv.Itoa(resp.StatusCode))
		return
	} else if resp.Json == nil {
		t.Error("failed to parse json from response")
		return
	}
}