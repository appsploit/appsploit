package nuclei

import (
	"appsploit/pkg/utils"
	"fmt"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// Executor represents template executor
type Executor struct {
	template        *Template
	baseURL         string
	customVariables map[string]interface{}
}

// NewExecutor creates a new executor
func NewExecutor(template *Template, baseURL string) *Executor {
	return &Executor{
		template:        template,
		baseURL:         strings.TrimRight(baseURL, "/"),
		customVariables: make(map[string]interface{}),
	}
}

// SetCustomVariables sets custom variables that override template variables
func (e *Executor) SetCustomVariables(vars map[string]interface{}) {
	if e.customVariables == nil {
		e.customVariables = make(map[string]interface{})
	}
	for k, v := range vars {
		e.customVariables[k] = v
	}
}

// Execute executes the template
func (e *Executor) Execute() (*Result, error) {
	// Compile matchers and extractors first
	if err := e.template.CompileMatchers(); err != nil {
		return nil, fmt.Errorf("failed to compile matchers: %w", err)
	}
	if err := e.template.CompileExtractors(); err != nil {
		return nil, fmt.Errorf("failed to compile extractors: %w", err)
	}

	result := &Result{
		Vulnerable:       false,
		ExtractedResults: make(map[string]string),
		MatchedData:      []string{},
		TemplateID:       e.template.ID,
		TemplateName:     e.template.Info.Name,
		Severity:         e.template.Info.Severity,
	}

	// Prepare variables map
	variables := e.prepareVariables()

	// Execute all HTTP requests sequentially
	allMatched := true
	var lastMatchedURL string
	var lastRequest string
	var lastResponse string

	for reqIndex, httpReq := range e.template.HTTP {
		requestMatched := false

		// Iterate through all paths for this request
		for _, path := range httpReq.Path {
			// Replace variables (including extracted values from previous requests)
			for k, v := range result.ExtractedResults {
				variables[k] = v
			}
			url := replaceVariables(path, variables)

			// Replace body variables if present
			body := httpReq.Body
			if body != "" {
				body = replaceVariables(body, variables)
			}

			// Execute HTTP request
			reqResult, err := e.executeHTTPRequest(&httpReq, url, body)
			if err != nil {
				// If this is not the last request and has no matchers, continue anyway
				if len(httpReq.Matchers) == 0 && reqIndex < len(e.template.HTTP)-1 {
					requestMatched = true
					break
				}
				continue
			}

			// Add delay after specific requests for CVE-2025-27817
			// After creating connector (request 1), wait 2 seconds
			if reqIndex == 0 && strings.Contains(url, "/connectors") && httpReq.Method == "POST" {
				time.Sleep(2 * time.Second)
			}
			// After restarting connector (request 2), wait 5 seconds
			if reqIndex == 1 && strings.Contains(url, "/restart") {
				time.Sleep(5 * time.Second)
			}

			// Check matchers (if any)
			if len(httpReq.Matchers) > 0 {
				matched := e.checkMatchers(&httpReq, reqResult)
				if matched {
					requestMatched = true
					lastMatchedURL = url
					lastRequest = reqResult.Request
					lastResponse = reqResult.Response

					// Extract data for use in subsequent requests
					if len(httpReq.Extractors) > 0 {
						extracted := e.extractData(&httpReq, reqResult)
						for k, v := range extracted {
							result.ExtractedResults[k] = v
						}
					}
					break // Move to next HTTP request
				}
			} else {
				// No matchers means always success
				requestMatched = true
				lastMatchedURL = url
				lastRequest = reqResult.Request
				lastResponse = reqResult.Response

				// Extract data even without matchers
				if len(httpReq.Extractors) > 0 {
					extracted := e.extractData(&httpReq, reqResult)
					for k, v := range extracted {
						result.ExtractedResults[k] = v
					}
				}
				break
			}
		}

		// If this request didn't match and it's required, mark as not vulnerable
		if !requestMatched {
			allMatched = false
			// Don't break - continue to execute remaining requests for cleanup
		}
	}

	// Set result based on whether all requests matched
	result.Vulnerable = allMatched
	result.MatchedURL = lastMatchedURL
	result.Request = lastRequest
	result.Response = lastResponse

	return result, nil
}

// prepareVariables prepares variables for replacement
func (e *Executor) prepareVariables() map[string]interface{} {
	variables := make(map[string]interface{})

	// Add built-in variables first
	variables["BaseURL"] = e.baseURL
	variables["baseurl"] = e.baseURL

	// Add template variables and replace dynamic functions in them
	for k, v := range e.template.Variables {
		// If the variable value is a string, replace dynamic functions
		if strVal, ok := v.(string); ok {
			variables[k] = replaceDynamicFunctions(strVal)
		} else {
			variables[k] = v
		}
	}

	// Override with custom variables (highest priority)
	for k, v := range e.customVariables {
		variables[k] = v
	}

	return variables
}

// HTTPResult represents HTTP request result
type HTTPResult struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	Request    string
	Response   string
}

// executeHTTPRequest executes HTTP request
func (e *Executor) executeHTTPRequest(httpReq *HTTP, url string, body string) (*HTTPResult, error) {
	client := utils.Http.Client()

	// Set headers
	for k, v := range httpReq.Headers {
		client.SetHeader(k, v)
	}

	var resp interface{}
	var err error
	var reqStr string

	// Build request string
	reqStr = fmt.Sprintf("%s %s", httpReq.Method, url)

	// Use provided body or fall back to httpReq.Body
	requestBody := body
	if requestBody == "" {
		requestBody = httpReq.Body
	}

	// Execute request based on method
	switch strings.ToUpper(httpReq.Method) {
	case "GET":
		resp, err = client.Get(url)
	case "POST":
		if requestBody != "" {
			client.SetBody(requestBody)
		}
		resp, err = client.Post(url)
	case "PUT":
		if requestBody != "" {
			client.SetBody(requestBody)
		}
		resp, err = client.Put(url)
	case "DELETE":
		resp, err = client.Delete(url)
	case "HEAD":
		resp, err = client.Head(url)
	case "OPTIONS":
		resp, err = client.Options(url)
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %s", httpReq.Method)
	}

	if err != nil {
		return nil, err
	}

	// 将interface{}转换为具体的响应类型
	restyResp, ok := resp.(*resty.Response)
	if !ok {
		return nil, fmt.Errorf("invalid response type")
	}

	result := &HTTPResult{
		StatusCode: restyResp.StatusCode(),
		Headers:    make(map[string]string),
		Body:       string(restyResp.Body()),
		Request:    reqStr,
		Response:   string(restyResp.Body()),
	}

	// Extract response headers
	for k, v := range restyResp.Header() {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	return result, nil
}

// checkMatchers checks matchers
func (e *Executor) checkMatchers(httpReq *HTTP, result *HTTPResult) bool {
	if len(httpReq.Matchers) == 0 {
		return true // 没有matcher默认匹配
	}

	matchersCondition := strings.ToLower(httpReq.MatchersCondition)
	matched := false

	for _, matcher := range httpReq.Matchers {
		matchResult := e.checkMatcher(&matcher, result)

		// 如果是negative，则取反
		if matcher.Negative {
			matchResult = !matchResult
		}

		if matchersCondition == "and" {
			if !matchResult {
				return false // AND条件，任意一个不匹配则返回false
			}
			matched = true
		} else { // or
			if matchResult {
				matched = true
				break // OR条件，任意一个匹配则返回true
			}
		}
	}

	return matched
}

// checkMatcher checks a single matcher
func (e *Executor) checkMatcher(matcher *Matcher, result *HTTPResult) bool {
	// Get content to match
	content := e.getMatcherContent(matcher.Part, result)

	switch strings.ToLower(matcher.Type) {
	case "status":
		matchResult := e.matchStatus(matcher.Status, result.StatusCode)
		return matchResult
	case "word", "words":
		matchResult := matchWords(matcher.Words, content, matcher.Condition, matcher.CaseInsensitive)
		return matchResult
	case "regex":
		matchResult := matchRegex(matcher.regexCompiled, content, matcher.Condition)
		return matchResult
	case "size":
		return e.matchSize(matcher.Size, len(content))
	case "dsl":
		// Prepare DSL data
		data := e.prepareDSLData(result)
		return matchDSL(matcher.dslCompiled, data, matcher.Condition)
	case "xpath":
		return matchXPath(matcher.XPath, content, matcher.Condition)
	default:
		return false
	}
}

// prepareDSLData prepares data map for DSL evaluation
func (e *Executor) prepareDSLData(result *HTTPResult) map[string]interface{} {
	data := make(map[string]interface{})

	// Add basic response data
	data["status_code"] = result.StatusCode
	data["body"] = result.Body
	data["response"] = result.Response
	data["request"] = result.Request
	data["content_length"] = len(result.Body)

	// Add headers
	for k, v := range result.Headers {
		// Normalize header names for DSL (replace - with _)
		normalizedKey := strings.ReplaceAll(strings.ToLower(k), "-", "_")
		data[normalizedKey] = v
	}

	// Add template variables
	for k, v := range e.template.Variables {
		data[k] = v
	}

	// Add built-in variables
	data["BaseURL"] = e.baseURL

	return data
}

// getMatcherContent gets content to match based on part
func (e *Executor) getMatcherContent(part string, result *HTTPResult) string {
	switch strings.ToLower(part) {
	case "body":
		return result.Body
	case "header":
		var headers strings.Builder
		for k, v := range result.Headers {
			headers.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
		return headers.String()
	case "all":
		var all strings.Builder
		all.WriteString(result.Request)
		all.WriteString("\n")
		all.WriteString(result.Response)
		return all.String()
	default:
		return result.Body
	}
}

// matchStatus matches status code
func (e *Executor) matchStatus(statuses []int, actualStatus int) bool {
	for _, status := range statuses {
		if status == actualStatus {
			return true
		}
	}
	return false
}

// matchSize matches size
func (e *Executor) matchSize(sizes []int, actualSize int) bool {
	for _, size := range sizes {
		if size == actualSize {
			return true
		}
	}
	return false
}

// extractData extracts data from HTTP result
func (e *Executor) extractData(httpReq *HTTP, result *HTTPResult) map[string]string {
	extracted := make(map[string]string)

	// Prepare data map for DSL and kval extractors
	data := e.prepareDSLData(result)

	for _, extractor := range httpReq.Extractors {
		content := e.getMatcherContent(extractor.Part, result)
		extractorResults := extractFromContent(&extractor, content, data)
		for k, v := range extractorResults {
			extracted[k] = v
		}
	}

	return extracted
}

// FormatResult formats result output
func (e *Executor) FormatResult(result *Result) string {
	if !result.Vulnerable {
		return "No vulnerability detected"
	}

	var output strings.Builder

	output.WriteString(fmt.Sprintf("[%s] %s\n", e.template.ID, e.template.Info.Name))
	output.WriteString(fmt.Sprintf("Severity: %s\n", e.template.Info.Severity))
	output.WriteString(fmt.Sprintf("Matched URL: %s\n", result.MatchedURL))

	if len(result.ExtractedResults) > 0 {
		output.WriteString("\nExtracted Results:\n")
		for name, value := range result.ExtractedResults {
			output.WriteString(fmt.Sprintf("  %s:\n%s\n", name, value))
		}
	}

	if result.Response != "" {
		output.WriteString("\nResponse Content:\n")
		// 限制输出长度
		if len(result.Response) > 2000 {
			output.WriteString(result.Response[:2000])
			output.WriteString("\n... (content too long, truncated)")
		} else {
			output.WriteString(result.Response)
		}
	}

	return output.String()
}
