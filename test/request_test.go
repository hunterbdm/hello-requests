package test

import (
	"crypto/tls"
	"fmt"
	request "github.com/hunterbdm/hello-requests"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
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
	for i := 0; i < 1; i++ {
		_, err := request.Do(request.Options{
			Method: "GET",
			URL: "https://www.yeezysupply.com/",
			Headers: request.Headers{
				"sec-ch-ua": "\"Chromium\";v=\"92\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"92\"",
				"sec-ch-ua-mobile": "?0",
				"upgrade-insecure-requests": "1",
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
				"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"sec-fetch-site": "none",
				"sec-fetch-mode": "navigate",
				"sec-fetch-user": "?1",
				"sec-fetch-dest": "document",
				"accept-encoding": "gzip, deflate, br",
				"accept-language": "en-US,en;q=0.9",
			},
			HeaderOrder: request.HeaderOrder{
				"sec-ch-ua",
				"sec-ch-ua-mobile",
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
			ClientSettings: &request.ClientSettings{
				IdleTimeoutTime: 5001 + i,
				SkipCertChecks: true,
				Proxy: "127.0.0.1:8888",
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
		URL: "https://fp-server-balancer-aa75aa0de443c8ad.elb.us-east-1.amazonaws.com/rc?bypass=encryption",
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

	t.Log(resp.Json)
}

func TestChromeFP2(t *testing.T) {
	resp, err := request.Do(request.Options{
		URL: "https://ezdiscord.xyz/fingerprint",
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

	t.Log(resp.Json)
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

func _TestBase64Body(t *testing.T) {
	jar := request.Jar()
	cs := request.ClientSettings{
		SkipCertChecks: true,
		//Proxy: "127.0.0.1:8888",
	}

	resp, err := request.Do(request.Options{
		Method: "POST",
		URL: "https://api.nike.com/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/tl",
		Headers: request.Headers{
			"sec-ch-ua": "\" Not A;Brand\";v=\"99\": \"Chromium\";v=\"90\": \"Google Chrome\";v=\"90\"",
			"sec-ch-ua-mobile": "?0",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
			"content-type": "application/octet-stream",
			"accept": "*/*",
			"origin": "https://api.nike.com",
			"sec-fetch-site": "same-origin",
			"sec-fetch-mode": "cors",
			"sec-fetch-dest": "empty",
			"referer": "https://api.nike.com/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-US,en;q=0.9",
			"x-kpsdk-ct": "024gqKyCwzGaMjNM9d5ptTyhMMkUJXlXq7QxRx2WeE0OosrARXxIOlWCZUp6mG4kqbv0xglTAD3wRY8yUGyAzmVfXDJCzffhiOn9qmDWn7ysCLArAZvDhpOPMt773lRn1nMZt0AOA7BFdsFGH6Rh9smrboB",
			"host": "api.nike.com",
		},
		HeaderOrder: request.HeaderOrder{
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"user-agent",
			"content-type",
			"accept",
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"x-kpsdk-ct",
			"host",
			"cookie",
			"content-length",
		},
		FollowRedirects: true,
		Jar: jar,
		ClientSettings: &cs,
		Body: "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",
		Base64Body: true,
	})

	if err != nil {
		t.Error(err)
		return
	} else {
		t.Log(resp.StatusCode)
	}
}

func _TestFastly(t *testing.T) {
	for i := 0; i < 1; i++ {
		resp, err := request.Do(request.Options{
			Method: "GET",
			URL: "https://cache-bwi5175.hosts.fastly.net/api/session",
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
				"Host": "www.footlocker.com",
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
				//Proxy: "127.0.0.1:8888",
				SkipCertChecks: true,
			},
		})

		if err != nil {
			t.Error(err)
			return
		} else {
			t.Log(resp.StatusCode, resp.Body)
		}
	}
}

func _TestFastly2(t *testing.T) {
	cartHeaders := map[string]string{
		"host": "www.footlocker.com",
	}
	requestUrl := "https://cache-bwi5175.hosts.fastly.net/api/session"
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "www.footlocker.com",
		},
	}
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
	}
	req, err := http.NewRequest("GET", requestUrl, nil)

	req.Host = "www.footlocker.com"

	if err != nil {
		fmt.Println("Error Initiating Request")
		fmt.Println(err)
		return
	}
	for key, value := range cartHeaders {
		req.Header.Set(key, value)
	}

	log.Println(req)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error Sending Request")
		fmt.Println(err)
		return
	}
	bs, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(bs))
}