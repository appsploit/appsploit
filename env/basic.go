package env

import (
	"appsploit/pkg/dto/env"
	"appsploit/pkg/dto/fingerprint/cache"
	"appsploit/pkg/dto/fingerprint/datamatch"
	dtoFramework "appsploit/pkg/dto/fingerprint/framework"
	"appsploit/pkg/fingerprint/framework"
	"appsploit/pkg/utils"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/ssst0n3/awesome_libs/log"
	"github.com/urfave/cli/v2"
	"strings"
)

func WebServer(ctx *cli.Context) (result printer.Interface) {
	serverInfo := ""
	webserverInfo := env.WebServer{
		Name:    "unknown",
		Version: "unknown",
	}
	errorData := error(nil)
	baseURL := utils.Http.FormatURL(ctx)

	if err := utils.Http.HttpCheck(baseURL); err != nil {
		log.Logger.Debugf("request error: %s\n", err)
		webserverInfo.Name = "error"
		webserverInfo.Version = "error"
		return webserverInfo
	}

	if serverInfo, errorData = utils.Http.GetServerInfo(baseURL); errorData != nil {
		log.Logger.Debugf("request error: %s\n", errorData)
		webserverInfo.Name = "error"
		webserverInfo.Version = "error"
	}
	if serverInfo != "" {
		if strings.Contains(serverInfo, "/") {
			if strings.Contains(serverInfo, " ") {
				serverInfo = strings.Split(serverInfo, " ")[0]
			}
			webserverInfo.Name = strings.Split(serverInfo, "/")[0]
			webserverInfo.Version = strings.Split(serverInfo, "/")[1]
		} else {
			webserverInfo.Name = serverInfo
		}
	}
	return webserverInfo
}

func Framework(ctx *cli.Context) (result printer.Interface) {
	frameworkInfo := env.Framework{
		Name:    "unknown",
		Version: "unknown",
	}
	baseURL := utils.Http.FormatURL(ctx)

	if err := utils.Http.HttpCheck(baseURL); err != nil {
		log.Logger.Debugf("request error: %s\n", err)
		frameworkInfo.Name = "error"
		frameworkInfo.Version = "error"
		return frameworkInfo
	}

	matchArgs := map[string]interface{}{
		"baseURL":         baseURL,
		"respCacheMap":    make(map[string]cache.RespCache),
		"regexpMatchList": []dtoFramework.RegexpMatch{},
		"hashMatchList":   []dtoFramework.HashMatch{},
		"matchCache":      "",
		"matchResult":     "",
	}

	for _, frameworkMatch := range framework.List {
		if matchArgs, frameworkInfo.Name = dataMatch(matchArgs, frameworkMatch.Basic); frameworkInfo.Name != "unknown" {
			for _, versionMatch := range frameworkMatch.Version {
				if matchArgs, frameworkInfo.Version = dataMatch(matchArgs, versionMatch); frameworkInfo.Version != "unknown" {
					break
				}
			}
		}
		if frameworkInfo.Name != "unknown" {
			break
		}
	}
	return frameworkInfo
}

func dataMatch(matchArgs map[string]interface{}, matchData dtoFramework.MatchData) (map[string]interface{}, string) {
	result := "unknown"
	matchArgs["matchResult"] = matchData.Name
	matchMap := []dtoFramework.MatchMap{
		{
			MatchList:  matchData.HeaderRegexpMatch,
			MatchType:  datamatch.Regexp,
			MatchCache: "Header",
			MatchFunc:  regexpMatch,
		},
		{
			MatchList:  matchData.BodyRegexpMatch,
			MatchType:  datamatch.Regexp,
			MatchCache: "BodyString",
			MatchFunc:  regexpMatch,
		},
		{
			MatchList:  matchData.BodyHash,
			MatchType:  datamatch.Hash,
			MatchCache: "BodyBytes",
			MatchFunc:  hashMatch,
		},
	}
	for _, match := range matchMap {
		switch match.MatchType {
		case datamatch.Regexp:
			matchArgs["regexpMatchList"] = match.MatchList
		case datamatch.Hash:
			matchArgs["hashMatchList"] = match.MatchList
		}
		matchArgs["matchCache"] = match.MatchCache
		matchArgs["respCacheMap"], result = match.MatchFunc(matchArgs)
		if result != "unknown" {
			break
		}
	}
	matchArgs["regexpMatchList"] = []dtoFramework.RegexpMatch{}
	matchArgs["hashMatchList"] = []dtoFramework.HashMatch{}
	return matchArgs, result
}

func getRespCache(respCacheMap map[string]cache.RespCache, baseURL string, path string) (map[string]cache.RespCache, cache.RespCache) {
	errorData := error(nil)
	respCache := cache.RespCache{}
	if cacheData, ok := respCacheMap[path]; ok {
		respCache = cacheData
	} else {
		reqURL, err := utils.Http.FormatURLPath(baseURL, path)
		if err != nil {
			log.Logger.Debugf("url error: %s\n", err)
		} else {
			if respCache, errorData = utils.Http.Req2RespCache(reqURL); errorData != nil {
				log.Logger.Debugf("request error: %s\n", errorData)
			} else {
				respCacheMap[path] = respCache
			}
		}
	}
	return respCacheMap, respCache
}

func regexpMatch(matchArgs map[string]interface{}) (map[string]cache.RespCache, string) {
	result := "unknown"
	baseURL := matchArgs["baseURL"].(string)
	respCacheMap := matchArgs["respCacheMap"].(map[string]cache.RespCache)
	regexpMatchList := matchArgs["regexpMatchList"].([]dtoFramework.RegexpMatch)
	matchCache := matchArgs["matchCache"].(string)

	for _, regexpData := range regexpMatchList {
		respCache := cache.RespCache{}
		respCacheMap, respCache = getRespCache(respCacheMap, baseURL, regexpData.Path)
		if match, err := utils.Common.StringRegexpMatch(regexpData.Regexp, utils.Common.GetStructValue(respCache, matchCache).(string)); err == nil {
			if match {
				result = matchArgs["matchResult"].(string)
				break
			}
		} else {
			log.Logger.Debugf("regexp match error: %s\n", err)
		}
	}
	return respCacheMap, result
}

func hashMatch(matchArgs map[string]interface{}) (map[string]cache.RespCache, string) {
	result := "unknown"
	baseURL := matchArgs["baseURL"].(string)
	respCacheMap := matchArgs["respCacheMap"].(map[string]cache.RespCache)
	hashMatchList := matchArgs["hashMatchList"].([]dtoFramework.HashMatch)
	matchCache := matchArgs["matchCache"].(string)

	for _, hashData := range hashMatchList {
		respCache := cache.RespCache{}
		respCacheMap, respCache = getRespCache(respCacheMap, baseURL, hashData.Path)
		if len(respCache.BodyHash) < hashData.Type+1 {
			for i := 0; len(respCache.BodyHash) < hashData.Type+1; i++ {
				respCache.BodyHash = append(respCache.BodyHash, "")
			}
		}
		if respCache.BodyHash[hashData.Type] == "" {
			if hash, err := utils.Common.DataHash(hashData.Type, utils.Common.GetStructValue(respCache, matchCache).([]byte)); err == nil {
				respCache.BodyHash[hashData.Type] = hash
				respCacheMap[hashData.Path] = respCache
			} else {
				log.Logger.Debugf("hash match error: %s\n", err)
			}
		}
		if hashData.Value == respCache.BodyHash[hashData.Type] {
			result = matchArgs["matchResult"].(string)
			break
		}
	}
	return respCacheMap, result
}
