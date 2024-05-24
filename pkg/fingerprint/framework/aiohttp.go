package framework

import (
	"appsploit/pkg/dto/fingerprint/framework"
)

var aiohttp = framework.Fingerprint{
	Basic: framework.MatchData{
		Name: "AIOHTTP",
		HeaderRegexpMatch: []framework.RegexpMatch{
			{Path: "/", Regexp: "Server:.*aiohttp/.*"},
		},
		BodyRegexpMatch: []framework.RegexpMatch{},
		BodyHash:        []framework.HashMatch{},
	},
	Version: []framework.MatchData{
		{
			Name: "3.9.0",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "aiohttp/3.9.0"},
			},
		},
		{
			Name: "3.9.1",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "aiohttp/3.9.1"},
			},
		},
		{
			Name: "3.9.2",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "aiohttp/3.9.2"},
			},
		},
		{
			Name: "3.9.3",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "aiohttp/3.9.3"},
			},
		},
	},
}
