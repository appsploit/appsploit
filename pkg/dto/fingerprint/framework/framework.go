package framework

import "appsploit/pkg/dto/fingerprint/cache"

type Fingerprint struct {
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
	MatchList  interface{}
	MatchType  int
	MatchCache string
	MatchFunc  func(matchArgs map[string]interface{}) (map[string]cache.RespCache, string)
}
