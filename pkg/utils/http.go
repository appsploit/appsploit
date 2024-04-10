package utils

import (
	"appsploit/internal/global"
	"appsploit/pkg/dto/fingerprint/cache"
	"crypto/tls"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/urfave/cli/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type utilsHttp struct{}

func (u *utilsHttp) Client() *resty.Request {
	httpTransport := new(http.Transport)
	if !global.HttpCertVerify {
		httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := resty.New().
		SetTimeout(time.Duration(global.HttpTimeout)*time.Second).
		SetTransport(httpTransport).
		SetHeader("User-Agent", global.HttpUserAgent)
	if global.HttpProxy != "" {
		if !strings.Contains(global.HttpProxy, "://") {
			global.HttpProxy = fmt.Sprintf("http://%s", global.HttpProxy)
		}
		client = client.SetProxy(global.HttpProxy)
	}
	return client.R()
}

func (u *utilsHttp) HttpCheck(url string) error {
	httpClient := *u.Client()
	_, err := httpClient.Head(url)
	return err
}

func (u *utilsHttp) GetServerInfo(url string) (string, error) {
	httpClient := *u.Client()
	if resp, err := httpClient.Head(url); err != nil {
		return "", err
	} else {
		return strings.ToLower(resp.Header().Get("Server")), error(nil)
	}
}

func (u *utilsHttp) FormatURL(ctx *cli.Context) string {
	proto := "http"
	if ctx.Bool("https") {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s:%d", proto, ctx.String("target"), ctx.Int("port"))
}

func (u *utilsHttp) FormatURLPath(baseURL string, path string) (string, error) {
	if newURL, err := url.Parse(baseURL); err != nil {
		return "", err
	} else {
		joinedURL := newURL.ResolveReference(&url.URL{Path: path})
		return joinedURL.String(), error(nil)
	}
}

func (u *utilsHttp) Req2RespCache(url string) (cache.RespCache, error) {
	respCache := cache.RespCache{}
	httpClient := *u.Client()
	if resp, err := httpClient.Get(url); err != nil {
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
