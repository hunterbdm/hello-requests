package test

import (
	request "github.com/hunterbdm/hello-requests"
	"net/url"
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

func TestPostRedirects(t *testing.T) {
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
	authToken = url.QueryEscape(authToken)

	body := "authenticity_token=" + authToken + "&g-recaptcha-response=03AGdBq24kvYPL4zvpdCPKi_hwIskwql8ZNqtCfYC2cftEV6w5_aZkYutut8O2NtWRD-ojEQWeMhSOZKav25il9FyJLJ84hqYdXnOhy8npgkIL828aP7rSQqNx71G5-tOEJGjHsVGwZSSHukvNTn8Gp4OmEsX8FMh4U_F8FMPucMbeGSHeDU72F2YcwZQ-69ejFbOOhUvlTx0AIk-VnLgL1W-HrZX6i5s0DmOMHsY93GDfCAtcVxtDE998R_9a4ux5rKtlwsBOGiheqgMGkEA7C_joA3e62CUrZb-PIOj0FBTGd9rLcN58CsTHA9eq-s2uHTNafQPWe29lzTnh6GfPr0Q_aXlyuxRh98byQPK4cXGMPhg5xMlib1v_7FX2jvFGA7C7WWbKffEUKthgxcOCJ_roPWVDsRp0hqKihNdXgVOUFFHDvvTRBix50IvcaqKLoOKembAylK762s_YmyG-1DbCSOsdNOoRbis4EMvxzuvUIoMmjasvvJioBCVBmUdkh49QUYAdDpdlwoXGyIiJNAQ-R0FZmDCTAUd9fRqPdSQCMLIS0z9MhiZeVv6k6541orKIdf7ijBTyy_kZgOYsHWgF9-0g9pHkD8PqQWo7gtDGljCiNXVhpPSoJD9htqGjcnU6_ihZiL8bJ1BtbU7LC5PDBLuEv5ovVRXvclYs4CgtBn6rNWxoNwprtDL-fxDYchxgllyaMiS6YYB8yzLsMvbLY4hXGrzEsEj31DkE02jkTtbQe3dUkpaVgvMvGe6ek1ky1WAAADjt4aEN05Emvo1J0DLVFuG6FrM5cWtmldNQ7YdNf9e0g-h9n0TMhM-tSemEFE0CKkmizo0gIiEwbof-34wrqNj4tIgsLgNDNatfwErD9dZAS6f50pzvYjD_Jmbjw_CftdpdwjU_XZu__MshNxFcjFLtkvMt5SWJFcgN9rg-5-KG9cP6m-Aar364PvipfPQBHqk7Dypk_yGbdZkg7hoH6Ajg6SuQdQTDPw9BnvtJToT6insOycwalV_UmS46m5cojkUrRzP3nR-jfhy_NS1Pts9EHx3Yk7kdBixbpA3GZStidgDyeTj1o5H8hAbAft6-ZPUczFVDD8iZqoRHX7J0HQiU4V8LKBSnyMe1fGap8NJjwHr8jC-FEsVdMwrtHZeN57jXEcMEkdl9U0QJydC6xfh5Lgp-bzFyciX69LlUs3lKws7nmGp_lS7wlemV3WlRzyETcv_28EuvvYqKfvTHGbg6C9Fpf-1KkhnBo0wIDkm1KcMPwrKWCoZauaAzRs3wPV3TTcciS6u-rCbGhPWrlRmQKcySgI6ReqVzMRTDHslzT7wvv7DtZkChx4l-bHuT7dhjZvtwB0CeuXQxi0HpaSCf3v6SudgqrQZ3ZGnKuJyBhzooK-sqzr_iyLBhG_TSEd89vbb7zQzmZTXqXS8TBx19qWmIHy4613bfajyKoOQdU6F7Qkal29gcxw-73Wajs_N_xzsHsyJF2iJ_9kyh3eP0GgX5xlcs5iz8xqxgEvPkduLZJEWHUSzBn0PCbFdda3dvKP4JRqHRHtSOdkw2mGyb6vKcn15_EG5JhSnFvZgW_1GMZwpdlclMwfDBQzM-AjVWOaWLjaTtQqpk-H1v14ezXcaLuyRuK-IMQ7_THrV5WOeqRuxlxXgEkehfuz4exqWhdrV5PolZuU3sbrl8sibTJT&data_via=cookie&commit="

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
		Body: body,
	})

	if err != nil {
		t.Error(err)
		return
	}
}