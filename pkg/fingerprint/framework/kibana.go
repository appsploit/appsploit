package framework

import (
	"appsploit/pkg/dto/fingerprint/framework"
)

var kibana = framework.Fingerprint{
	Basic: framework.MatchData{
		Name: "Kibana",
		HeaderRegexpMatch: []framework.RegexpMatch{
			{Path: "/", Regexp: "kbn-name:.*"},
		},
		BodyRegexpMatch: []framework.RegexpMatch{},
		BodyHash:        []framework.HashMatch{},
	},
	Version: []framework.MatchData{
		{
			Name: "7.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "kbn-version: 7.*"},
			},
		},
		{
			Name: "6.x",
			HeaderRegexpMatch: []framework.RegexpMatch{
				{Path: "/", Regexp: "kbn-version: 6.*"},
			},
		},
	},
}
