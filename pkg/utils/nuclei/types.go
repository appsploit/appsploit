package nuclei

import (
	"regexp"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
)

// Template represents Nuclei template structure
type Template struct {
	ID        string    `yaml:"id"`
	Info      Info      `yaml:"info"`
	Variables Variables `yaml:"variables"`
	HTTP      []HTTP    `yaml:"http"`
	TCP       []TCP     `yaml:"tcp"`
	Network   []TCP     `yaml:"network"` // network is alias for tcp
}

// Info represents template information
type Info struct {
	Name           string                 `yaml:"name"`
	Author         interface{}            `yaml:"author"` // can be string or []string
	Severity       string                 `yaml:"severity"`
	Description    string                 `yaml:"description"`
	Reference      interface{}            `yaml:"reference"` // can be string or []string
	Classification Classification         `yaml:"classification"`
	Tags           interface{}            `yaml:"tags"` // can be string or []string
	Metadata       map[string]interface{} `yaml:"metadata"`
}

// Classification represents vulnerability classification
type Classification struct {
	CVSSMetrics string      `yaml:"cvss-metrics"`
	CVSSScore   float64     `yaml:"cvss-score"`
	CVEID       string      `yaml:"cve-id"`
	CWEID       interface{} `yaml:"cwe-id"` // can be string or []string
}

// Variables represents template variables
type Variables map[string]interface{}

// HTTP represents HTTP request configuration
type HTTP struct {
	Method            string              `yaml:"method"`
	Path              []string            `yaml:"path"`
	Raw               []string            `yaml:"raw"`
	Headers           map[string]string   `yaml:"headers"`
	Body              string              `yaml:"body"`
	Matchers          []Matcher           `yaml:"matchers"`
	MatchersCondition string              `yaml:"matchers-condition"`
	Extractors        []Extractor         `yaml:"extractors"`
	AttackType        string              `yaml:"attack"`
	Payloads          map[string][]string `yaml:"payloads"`
	Threads           int                 `yaml:"threads"`
	StopAtFirstMatch  bool                `yaml:"stop-at-first-match"`
	MaxRedirects      int                 `yaml:"max-redirects"`
	FollowRedirects   bool                `yaml:"redirects"`
	CookieReuse       bool                `yaml:"cookie-reuse"`
	ReadAll           bool                `yaml:"read-all"`
	MaxSize           int                 `yaml:"max-size"`
	ReqCondition      bool                `yaml:"req-condition"`
	HostRedirects     bool                `yaml:"host-redirects"`
}

// TCP represents TCP/Network request configuration
type TCP struct {
	Host              []string    `yaml:"host"`
	Inputs            []TCPInput  `yaml:"inputs"`
	ReadSize          int         `yaml:"read-size"`
	ReadAll           bool        `yaml:"read-all"`
	Matchers          []Matcher   `yaml:"matchers"`
	MatchersCondition string      `yaml:"matchers-condition"`
	Extractors        []Extractor `yaml:"extractors"`
}

// TCPInput represents TCP input data
type TCPInput struct {
	Data string `yaml:"data"`
	Type string `yaml:"type"` // hex, text
	Read int    `yaml:"read"`
}

// Matcher represents a matcher configuration
type Matcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	Size            []int    `yaml:"size"`
	DSL             []string `yaml:"dsl"`
	Binary          []string `yaml:"binary"`
	XPath           []string `yaml:"xpath"`
	Encoding        string   `yaml:"encoding"`
	Negative        bool     `yaml:"negative"`
	Internal        bool     `yaml:"internal"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	MatchAll        bool     `yaml:"match-all"`
	Name            string   `yaml:"name"`

	// Compiled fields (not from YAML)
	regexCompiled []*regexp.Regexp
	dslCompiled   []*govaluate.EvaluableExpression
}

// Extractor represents an extractor configuration
type Extractor struct {
	Type            string   `yaml:"type"`
	Name            string   `yaml:"name"`
	Part            string   `yaml:"part"`
	Group           int      `yaml:"group"`
	Regex           []string `yaml:"regex"`
	KVal            []string `yaml:"kval"`
	JSON            []string `yaml:"json"`
	XPath           []string `yaml:"xpath"`
	Attr            string   `yaml:"attr"`
	DSL             []string `yaml:"dsl"`
	Internal        bool     `yaml:"internal"`
	CaseInsensitive bool     `yaml:"case-insensitive"`

	// Compiled fields (not from YAML)
	regexCompiled []*regexp.Regexp
	jsonCompiled  []*gojq.Code
	dslCompiled   []*govaluate.EvaluableExpression
}

// Result represents execution result
type Result struct {
	Vulnerable       bool              // whether vulnerability exists
	MatchedURL       string            // matched URL/Host
	Request          string            // request content
	Response         string            // response content
	ExtractedResults map[string]string // extracted results
	MatchedData      []string          // matched data
	TemplateName     string            // template name
	TemplateID       string            // template ID
	Severity         string            // severity level
}

// TemplateInfo represents template information for listing
type TemplateInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      []string `json:"author"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	FilePath    string   `json:"file_path"`
}
