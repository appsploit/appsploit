package utils

import (
	"appsploit/pkg/dto/finderprint/cache"
	"crypto/tls"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/urfave/cli/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type utilsHttp struct {
	httpOptions
}

type httpOptions struct {
	UserAgent  string
	CertVerify bool
	Timeout    time.Duration
	Proxy      string
}

func (u *utilsHttp) Client() *resty.Request {
	httpTransport := new(http.Transport)
	if u.UserAgent == "" {
		u.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
	}
	if !u.CertVerify {
		httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if u.Timeout <= 0 {
		u.Timeout = 15
	}
	client := resty.New().
		SetTimeout(u.Timeout*time.Second).
		SetTransport(httpTransport).
		SetHeader("User-Agent", u.UserAgent)
	if u.Proxy != "" {
		client = client.SetProxy(u.Proxy)
	}
	return client.R()
}

func (u *utilsHttp) GetServerInfo(url string) (string, error) {
	httpClient := *Http.Client()
	resp, err := httpClient.Head(url)
	if err != nil {
		return "", err
	}
	return strings.ToLower(resp.Header().Get("Server")), error(nil)
}

func (u *utilsHttp) FormatURL(ctx *cli.Context) string {
	proto := "http"
	if ctx.Bool("https") {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s:%d", proto, ctx.String("target"), ctx.Int("port"))
}

func (u *utilsHttp) FormatURLPath(baseURL string, path string) (string, error) {
	newURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	joinedURL := newURL.ResolveReference(&url.URL{Path: path})
	return joinedURL.String(), error(nil)
}

func (u *utilsHttp) Request2RespCache(url string) (cache.RespCache, error) {
	respCache := cache.RespCache{}
	httpClient := *Http.Client()
	resp, err := httpClient.Get(url)
	if err != nil {
		return respCache, err
	} else {
		for key, value := range resp.Header() {
			respCache.Header += fmt.Sprintf("%s: %s\n", key, strings.Join(value, "|"))
		}
		respCache.BodyBytes = resp.Body()
		respCache.BodyString = string(resp.Body())
	}
	return respCache, error(nil)
}
