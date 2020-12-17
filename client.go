package request

import (
	"github.com/hunterbdm/hello-requests/http"
	"github.com/hunterbdm/hello-requests/mimic"
	"github.com/hunterbdm/hello-requests/utils"
	"strconv"
	"sync"
	"time"
)

var (
	defaultClientSettings = ClientSettings{
		IdleTimeoutTime: 10000,
		RequestTimeoutTime: 10000,
		MimicBrowser: "chrome",
	}

	httpClientMap = map[string]http.Client{}
	httpClientMapMutex = sync.RWMutex{}
)

type ClientSettings struct {
	IdleTimeoutTime int
	RequestTimeoutTime int

	FollowRedirects bool
	FollowHostRedirects bool
	SkipCertChecks bool

	Proxy string
	MimicBrowser string
}

// Fingerprint returns a string representation of the ClientSettings
func (cs *ClientSettings) Fingerprint() string {
	return strconv.Itoa(cs.IdleTimeoutTime) +
		strconv.Itoa(cs.RequestTimeoutTime) +
		strconv.FormatBool(cs.FollowRedirects) +
		strconv.FormatBool(cs.FollowHostRedirects) +
		strconv.FormatBool(cs.SkipCertChecks) +
		cs.Proxy +
		cs.MimicBrowser
}

// AddDefaults combines the options from the provided
// ClientSettings and the defaultClientSettings
func (cs *ClientSettings) AddDefaults() {
	if cs.IdleTimeoutTime == 0 {
		cs.IdleTimeoutTime = defaultClientSettings.IdleTimeoutTime
	}

	if cs.RequestTimeoutTime == 0 {
		cs.RequestTimeoutTime = defaultClientSettings.RequestTimeoutTime
	}

	if cs.MimicBrowser == "" || mimic.GetMimicSettings(cs.MimicBrowser) == nil {
		cs.MimicBrowser = defaultClientSettings.MimicBrowser
	}
}


// SetDefaultClientSettings overrides default ClientSettings config
func SetDefaultClientSettings(cs ClientSettings) {
	defaultClientSettings = cs
}

// GetHttpClient returns mapped http Clients
func GetHttpClient(cs *ClientSettings) *http.Client {
	fp := cs.Fingerprint()

	httpClientMapMutex.RLock()
	if client, ok := httpClientMap[fp]; ok {
		httpClientMapMutex.RUnlock()
		return &client
	}
	httpClientMapMutex.RUnlock()

	newClient := setupHttpClient(cs)

	httpClientMapMutex.Lock()
	httpClientMap[fp] = newClient
	httpClientMapMutex.Unlock()

	return &newClient
}

// setupHttpClient creates a http.Client and http.Transport
// that follows the options in the ClientSettings
func setupHttpClient(cs *ClientSettings) http.Client {
	mimicSettings := mimic.GetMimicSettings(cs.MimicBrowser)

	tp := http.Transport{
		IdleConnTimeout: time.Millisecond * time.Duration(cs.IdleTimeoutTime),
		MimicSettings: mimicSettings,
		SkipCertChecks: cs.SkipCertChecks,
	}

	// Add proxy to Transport
	if cs.Proxy != "" {
		proxyUrl, err := utils.ParseProxy(cs.Proxy)

		if err == nil {
			tp.Proxy = http.ProxyURL(proxyUrl)
		}
	}

	client := http.Client{
		Timeout: time.Millisecond * time.Duration(cs.RequestTimeoutTime),
		Transport: &tp,
	}

	if !cs.FollowRedirects && cs.FollowHostRedirects {
		client.CheckRedirect = followHostRedirects
	} else if !cs.FollowRedirects {
		client.CheckRedirect = followNoRedirects
	}

	// TODO SkipCertChecks
	// TODO MimicBrowser

	return client
}

// followHostRedirects is a CheckRedirect function that will only
// follow if the redirect Path matches the previous requests Path
func followHostRedirects(req *http.Request, via []*http.Request) error {
	lastRequest := via[len(via) - 1]

	if req.URL.Path == lastRequest.URL.Path {
		return nil
	}

	return http.ErrUseLastResponse
}

// followNoRedirects is a CheckRedirect function that not follow any redirects
func followNoRedirects(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}