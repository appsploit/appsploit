package framework

import (
	"appsploit/pkg/dto/fingerprint/framework"
)

var axios = framework.Fingerprint{
	Basic: framework.MatchData{
		Name: "Axios",
		HeaderRegexpMatch: []framework.RegexpMatch{
			{Path: "/", Regexp: "Server:.*axios/.*"},
		},
		BodyRegexpMatch: []framework.RegexpMatch{},
		BodyHash:        []framework.HashMatch{},
	},
	Version: []framework.MatchData{
		{
			Name: "1.9.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.9.*"},
			},
		},
		{
			Name: "1.8.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.8.*"},
			},
		},
		{
			Name: "1.7.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.7.*"},
			},
		},
		{
			Name: "1.6.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.6.*"},
			},
		},
		{
			Name: "1.5.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.5.*"},
			},
		},
		{
			Name: "1.4.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.4.*"},
			},
		},
		{
			Name: "1.3.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.3.*"},
			},
		},
		{
			Name: "1.2.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.2.*"},
			},
		},
		{
			Name: "1.1.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/1.1.*"},
			},
		},
		{
			Name: "0.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "axios/0.*"},
			},
		},
	},
}
