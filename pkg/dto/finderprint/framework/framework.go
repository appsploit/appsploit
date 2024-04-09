package framework

import "appsploit/pkg/dto/finderprint/cache"

type Finderprint struct {
	Basic   MatchData
	Version []MatchData
}

type MatchData struct {
	Name              string
	HeaderRegexpMatch []RegexpMatch
	BodyRegexpMatch   []RegexpMatch
	BodyHash          []HashMatch
}

type RegexpMatch struct {
	Path   string
	Regexp string
}

type HashMatch struct {
	Path  string
	Type  int
	Value string
}

type MatchMap struct {
	MatchList        interface{}
	MatchType        int
	MatchStructField string
	MatchFunc        func(matchArgs map[string]interface{}) (map[string]cache.RespCache, string)
}
