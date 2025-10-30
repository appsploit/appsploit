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
		return strings.ToLower(strings.TrimSpace(resp.Header().Get("Server"))), error(nil)
	}
}

func (u *utilsHttp) FormatURL(ctx *cli.Context) string {
	// 优先使用url参数
	if urlStr := ctx.String("url"); urlStr != "" {
		// 如果url不包含协议，添加http://
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			urlStr = "http://" + urlStr
		}
		// 移除末尾的斜杠
		return strings.TrimRight(urlStr, "/")
	}

	// 回退到target/port/tls参数（用于非HTTP漏洞）
	target := ctx.String("target")
	if target == "" {
		return ""
	}

	proto := "http"
	if ctx.Bool("tls") {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s:%d", proto, target, ctx.Int("port"))
}

func (u *utilsHttp) FormatURLPath(baseURL string, path string) (string, error) {
	if newURL, err := url.Parse(baseURL); err != nil {
		return "", err
	} else {
		joinedURL := newURL.ResolveReference(&url.URL{Path: path})
		return joinedURL.String(), error(nil)
	}
}

func (u *utilsHttp) Get(url string) (string, error) {
	response := ""
	httpClient := *u.Client()
	if resp, err := httpClient.Get(url); err != nil {
		return response, err
	} else {
		for key, value := range resp.Header() {
			response += fmt.Sprintf("%s: %s\n", key, strings.Join(value, "|"))
		}
		response += "\n" + resp.String()
	}
	return response, error(nil)
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
		respCache.BodyString = resp.String()
	}
	return respCache, error(nil)
}
