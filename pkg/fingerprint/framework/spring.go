package framework

import (
	"appsploit/pkg/dto/fingerprint/framework"
	"appsploit/pkg/dto/hash"
)

var spring = framework.Fingerprint{
	Basic: framework.MatchData{
		Name: "Spring Framework",
		HeaderRegexpMatch: []framework.RegexpMatch{
			{Path: "/", Regexp: "X-Application-Context"},
		},
		BodyRegexpMatch: []framework.RegexpMatch{
			{Path: "/testtttttttt", Regexp: "Whitelabel Error Page"},
		},
		BodyHash: []framework.HashMatch{
			{Path: "/favicon.ico", Type: hash.MD5, Value: "0488faca4c19046b94d07c3ee83cf9d6"},
		},
	},
	Version: []framework.MatchData{
		{
			Name: "1.0.0",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "v1.0.0-xxxxx"},
			},
			BodyRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "v1.0.0-xxxxx"},
			},
			BodyHash: []framework.HashMatch{
				{Path: "/", Type: hash.MD5, Value: "md5-0488faca4c19046b94d07c3ee83cf9d6"},
			},
		},
	},
}
