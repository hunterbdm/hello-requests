package test

import (
	request "github.com/hunterbdm/hello-requests"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// go test ./test -v

func _TestGoogle(t *testing.T) {
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

func _TestShopify(t *testing.T) {
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

func _TestYS(t *testing.T) {
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

func _TestChromeFP(t *testing.T) {
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

func _TestFirefoxFP(t *testing.T) {
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

func _TestBrotli(t *testing.T) {
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

func _TestSupremeIp(t *testing.T) {
	_, err := request.Do(request.Options{
		Method: "GET",
		URL: "https://151.101.46.133/shop.json",
		Headers: request.Headers{
			"host": "www.supremenewyork.com",
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
		ClientSettings: &request.ClientSettings{
			SkipCertChecks: true,
		},
	})

	if err != nil {
		t.Error(err)
		return
	}
}

func _TestH2Push(t *testing.T) {
	_, err := request.Do(request.Options{
		Method: "GET",
		URL: "https://www.nike.com/w/new-mens-clothing-3n82yz6ymx6znik1",
		Headers: request.Headers{
			"pragma": "no-cache",
			"cache-control": "no-cache",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site": "same-origin",
			"sec-fetch-mode": "navigate",
			"sec-fetch-user": "?1",
			"sec-fetch-dest": "document",
			"referer": "https://www.nike.com/w/new-mens-clothing-3n82yz6ymx6znik1",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-US,en;q=0.9",
		},
		HeaderOrder: request.HeaderOrder{
			"pragma",
			"cache-control",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
		},
	})

	if err != nil {
		t.Error(err)
		return
	}
}

func _TestHeaders(t *testing.T) {
	_, err := request.Do(request.Options{
		Method: "GET",
		URL: "https://www.nike.com/w/new-mens-clothing-3n82yz6ymx6znik1",
		Headers: request.Headers{
			"pragma": "no-cache",
			"cache-control": "no-cache",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site": "same-origin",
			"sec-fetch-mode": "navigate",
			"sec-fetch-user": "?1",
			"sec-fetch-dest": "document",
			"referer": "https://www.nike.com/w/new-mens-clothing-3n82yz6ymx6znik1",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-US,en;q=0.9",
			//"X-custom-header": "custom value",
		},
		HeaderOrder: request.HeaderOrder{
			"pragma",
			"cache-control",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"X-custom-header",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
		},
		ClientSettings: &request.ClientSettings{
			SkipCertChecks: true,
			Proxy: "127.0.0.1:8888",
		},
	})

	if err != nil {
		t.Error(err)
		return
	}
}

func _TestGetRedirects(t *testing.T) {
	_, err := request.Do(request.Options{
		Method: "GET",
		URL: "https://kith.com/checkout",
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
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"cookie",
		},
		FollowRedirects: true,
		Jar: request.Jar(),
		ClientSettings: &request.ClientSettings{
			SkipCertChecks: true,
			Proxy: "127.0.0.1:8888",
		},
	})

	if err != nil {
		t.Error(err)
		return
	}
}

func _TestPostRedirects(t *testing.T) {
	jar := request.Jar()
	cs := request.ClientSettings{
		SkipCertChecks: true,
		//Proxy: "127.0.0.1:8888",
	}

	resp, err := request.Do(request.Options{
		Method: "GET",
		URL: "https://kith.com/checkpoint",
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
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"cookie",
		},
		FollowRedirects: true,
		Jar: jar,
		ClientSettings: &cs,
	})


	if err != nil {
		t.Error(err)
		return
	}


	authTokenRegex, err := regexp.Compile("name=\"authenticity_token\" value=\"[^\"]+")
	if err != nil {
		t.Error(err)
		return
	}
	authToken := authTokenRegex.FindString(resp.Body)
	authToken = strings.Replace(authToken, "name=\"authenticity_token\" value=\"", "", -1)

	_, err = request.Do(request.Options{
		Method: "POST",
		URL: "https://kith.com/checkpoint",
		Headers: request.Headers{
			//"content-length": "1861",
			"cache-control": "max-age=0",
			"upgrade-insecure-requests": "1",
			"origin": "https://kith.com",
			"content-type": "application/x-www-form-urlencoded",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site": "same-origin",
			"sec-fetch-mode": "navigate",
			"sec-fetch-user": "?1",
			"sec-fetch-dest": "document",
			"referer": "https://kith.com/checkpoint",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-US,en;q=0.9",
			"x-extra-header": "true",
		},
		HeaderOrder: request.HeaderOrder{
			"content-length",
			"cache-control",
			"upgrade-insecure-requests",
			"origin",
			"content-type",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
		},
		FollowRedirects: true,
		Jar: jar,
		ClientSettings: &cs,
		Form: request.JSON{
			"authenticity_token": authToken,
			"g-recaptcha-response": "whatever",
			"data_via": "cookie",
			"commit": "",
		},
	})

	if err != nil {
		t.Error(err)
		return
	}
}