hello-requests
=========

Golang based request client made to mimic modern browsers and operating systems

Notable Features:
* Changable client hello messages
* http2 support
* Header ordering
* Proxy support
* Websocket server so the request client can be easily used from other programming language
    - aes 256 encryption
    - path checking
    - file name checking

## Installation

```bash
$ go get github.com/hunterbdm/hello-requests
```

## Structs

```go
// Options are the options sent to start a request
type Options struct {
	ID           string
	Method       string // (default: GET)
	URL          string // required
	Headers      map[string]string
	HeaderOrder  []string
	Body         string
	Proxy        string // optional
	MimicBrowser string // (default: Chrome)
	Jar          *cookiejar.Jar
}

// Response is the results of the request
type Response struct {
	Error      error
	StatusCode int
	Headers    map[string][]string
	Body       string
	Time       int // Total time the request took
}
```

## Websockets (connector build)

* Incoming requests are in JSON format and should have the same fields as request.Options
* Outgoing responses are also in JSON format and have the same fields as request.Response
* AES-256 encryption can be enabled by providing a 32 character `cipherKey` in [connector/main.go](https://github.com/hunterbdm/hello-requests/tree/master/connector/main.go)
    - If set all messages will be encrypted/decrypted with the provided cipher key
* You can force the app to only run when the executable matches certain names by editing `validFileNames` in [connector/main.go](https://github.com/hunterbdm/hello-requests/tree/master/connector/main.go)
* You can force the app to only run when the path has a matching string by editing `validPaths` in [connector/main.go](https://github.com/hunterbdm/hello-requests/tree/master/connector/main.go)
* A `devKey` can be set in [connector/main.go](https://github.com/hunterbdm/hello-requests/tree/master/connector/main.go) and if it matches `HR_DEV_KEY` in your env variables it will bypass all security checks

## Usage (Golang)

```go
import (
	"strconv"
	request "hello-requests"
)

jar := request.Jar()

resp, err := request.Do(request.Options{
    Method: "GET",
    URL:    "https://ja3er.com/json",
    Headers: request.Headers{
        "Host":                      "ja3er.com", // Not needed, will be set automatically
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36",
        "Sec-Fetch-Dest":            "document",
        "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site":            "none",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-User":            "?1",
        "Accept-Encoding":           "gzip, deflate, br",
        "Accept-Language":           "en-US,en;q=0.9",
    },
    HeaderOrder: request.HeaderOrder{
        "Host",
        "Connection",
        "Upgrade-Insecure-Requests",
        "User-Agent",
        "Sec-Fetch-Dest",
        "Accept",
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-User",
        "Accept-Encoding",
        "Accept-Language",
    },
    //Proxy:        "127.0.0.1:8888",
    MimicBrowser: request.CHROME,
    Jar:          jar,
})

if err != nil {
    log.Println(err)
} else {
    log.Println("Status: " + strconv.Itoa(resp.StatusCode))
    log.Println("Body: " + resp.Body)
}

// 2020/04/06 23:31:53 Status: 200
// 2020/04/06 23:31:53 Body: {"ja3_hash":"66918128f1b9b03303d77c6f2eefd128", "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"}
```

## Usage (Outside Golang)

#### Setup
1. Go into `hello-requests/connector/main.go` and configure all the security related variables to your liking
2. Build the app. `go build`
3. Execute the app with your preferred port specified as the first argument. `connector.exe 5183` 
4. Connect to the websocket at `127.0.0.1:5183/req`

#### Usage
1. Build your request options in JSON format and specify an `ID`
2. Encrypt if needed and send the payload over the websocket
3. Wait for response from websocket (decrypt if needed)
4. Match `ID` on the response to know where it belongs