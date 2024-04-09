package framework

import (
	"appsploit/pkg/dto/finderprint/framework"
	"appsploit/pkg/dto/hash"
)

var testtest = framework.Finderprint{
	Basic: framework.MatchData{
		Name: "Test Framework",
		HeaderRegexpMatch: []framework.RegexpMatch{
			//{Path: "/", Regexp: "BWS"},
			{Path: "/", Regexp: "BWS"},
		},
		BodyRegexpMatch: []framework.RegexpMatch{
			{Path: "/", Regexp: "testttttttttt"},
		},
		BodyHash: []framework.HashMatch{
			{Path: "/favicon.ico", Type: hash.MD5, Value: "0488faca4c19046b94d07c3ee83cf9d6"},
			{Path: "/favicon.ico", Type: hash.SHA256, Value: "0488faca4c19046b94d07c3ee83cf9d6"},
			{Path: "/test", Type: hash.SHA1, Value: "0488faca4c19046b94d07c3ee83cf9d6"},
		},
	},
	Version: []framework.MatchData{
		{
			Name: "1.0.0",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "baidu"},
			},
			BodyRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "testttttttttt"},
			},
			BodyHash: []framework.HashMatch{
				{Path: "/", Type: hash.MD5, Value: "0488faca4c19046b94d07c3ee83cf9d6"},
				{Path: "/test", Type: hash.SHA1, Value: "0488faca4c19046b94d07c3ee83cf9d6"},
			},
		},
	},
}
