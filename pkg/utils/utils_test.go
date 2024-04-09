package utils

import (
	"appsploit/pkg/dto/hash"
	"strings"
	"testing"
)

func TestUtilsHttp_Client(t *testing.T) {
	httpClient := *Http.Client()
	resp, err := httpClient.Head("https://www.huaweicloud.com")
	if err != nil {
		t.Error(err)
		return
	}
	for key, value := range resp.Header() {
		t.Logf("%s: %s\n", key, strings.Join(value, "|"))
	}

	t.Log(resp.String())
}

func TestUtilsHttp_GetServerInfo(t *testing.T) {
	serverInfo, err := Http.GetServerInfo("https://www.baidu.com")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(serverInfo)
}

func TestUtilsHttp_Request2RespCache(t *testing.T) {
	respCache, err := Http.Request2RespCache("https://www.baidu.com")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(respCache.Header)
	t.Log(respCache.BodyString)
	t.Log(respCache.BodyBytes)
}

func TestUtilsDataHash_Hash(t *testing.T) {
	hashResult, err := Common.DataHash(hash.MD5, []byte("test"))
	if err != nil {
		t.Error(err)
	}
	t.Log(hashResult)
}
