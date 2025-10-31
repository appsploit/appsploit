package nuclei

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"
	"github.com/projectdiscovery/dsl"
)

// matchWords matches word patterns in content
func matchWords(words []string, content string, condition string, caseInsensitive bool) bool {
	if len(words) == 0 {
		return false
	}

	if caseInsensitive {
		content = strings.ToLower(content)
	}

	condition = strings.ToLower(condition)
	if condition == "" {
		condition = "or"
	}

	matched := 0

	for _, word := range words {
		searchWord := word
		if caseInsensitive {
			searchWord = strings.ToLower(word)
		}

		if strings.Contains(content, searchWord) {
			if condition == "or" {
				return true
			}
			matched++
		} else if condition == "and" {
			return false
		}
	}

	return condition == "and" && matched == len(words)
}

// matchRegex matches regex patterns in content (using pre-compiled regexes)
func matchRegex(compiled []*regexp.Regexp, content string, condition string) bool {
	if len(compiled) == 0 {
		return false
	}

	condition = strings.ToLower(condition)
	if condition == "" {
		condition = "or"
	}

	matched := 0

	for _, re := range compiled {
		if re.MatchString(content) {
			if condition == "or" {
				return true
			}
			matched++
		} else if condition == "and" {
			return false
		}
	}

	return condition == "and" && matched == len(compiled)
}

// matchDSL matches DSL expressions against data
func matchDSL(compiled []*govaluate.EvaluableExpression, data map[string]interface{}, condition string) bool {
	if len(compiled) == 0 {
		return false
	}

	condition = strings.ToLower(condition)
	if condition == "" {
		condition = "or"
	}

	matched := 0

	for _, expr := range compiled {
		result, err := expr.Evaluate(data)
		if err != nil {
			if condition == "and" {
				return false
			}
			continue
		}

		boolResult, ok := result.(bool)
		if !ok || !boolResult {
			if condition == "and" {
				return false
			}
			continue
		}

		if condition == "or" {
			return true
		}
		matched++
	}

	return condition == "and" && matched == len(compiled)
}

// matchXPath matches XPath expressions in HTML/XML content
func matchXPath(xpaths []string, content string, condition string) bool {
	if len(xpaths) == 0 {
		return false
	}

	condition = strings.ToLower(condition)
	if condition == "" {
		condition = "or"
	}

	// Determine if content is XML or HTML
	isXML := strings.HasPrefix(content, "<?xml")

	matched := 0

	for _, xpath := range xpaths {
		var nodeCount int
		var err error

		if isXML {
			doc, e := xmlquery.Parse(strings.NewReader(content))
			if e != nil {
				if condition == "and" {
					return false
				}
				continue
			}
			nodes, e := xmlquery.QueryAll(doc, xpath)
			err = e
			nodeCount = len(nodes)
		} else {
			doc, e := htmlquery.Parse(strings.NewReader(content))
			if e != nil {
				if condition == "and" {
					return false
				}
				continue
			}
			nodes, e := htmlquery.QueryAll(doc, xpath)
			err = e
			nodeCount = len(nodes)
		}

		if err != nil || nodeCount == 0 {
			if condition == "and" {
				return false
			}
			continue
		}

		if condition == "or" {
			return true
		}
		matched++
	}

	return condition == "and" && matched == len(xpaths)
}

// extractFromContent extracts data from content using various methods
func extractFromContent(extractor *Extractor, content string, data map[string]interface{}) map[string]string {
	extracted := make(map[string]string)

	switch strings.ToLower(extractor.Type) {
	case "regex":
		extracted = extractRegex(extractor, content)
	case "kval":
		extracted = extractKVal(extractor, data)
	case "json":
		extracted = extractJSON(extractor, content)
	case "xpath":
		extracted = extractXPath(extractor, content)
	case "dsl":
		extracted = extractDSL(extractor, data)
	}

	return extracted
}

// extractRegex extracts data using regex patterns
func extractRegex(extractor *Extractor, content string) map[string]string {
	results := make(map[string]string)

	groupPlusOne := extractor.Group + 1

	for _, re := range extractor.regexCompiled {
		submatches := re.FindAllStringSubmatch(content, -1)

		var matches []string
		for _, match := range submatches {
			if len(match) < groupPlusOne {
				continue
			}
			matchString := match[extractor.Group]
			matches = append(matches, matchString)
		}

		if len(matches) > 0 {
			name := extractor.Name
			if name == "" {
				name = "extracted"
			}
			results[name] = strings.Join(matches, "\n")
		}
	}

	return results
}

// extractKVal extracts key-value pairs from data map
func extractKVal(extractor *Extractor, data map[string]interface{}) map[string]string {
	results := make(map[string]string)

	// Normalize data keys if case-insensitive
	if extractor.CaseInsensitive {
		normalizedData := make(map[string]interface{})
		for k, v := range data {
			if s, ok := v.(string); ok {
				v = strings.ToLower(s)
			}
			normalizedData[strings.ToLower(k)] = v
		}
		data = normalizedData
	}

	for _, key := range extractor.KVal {
		if value, ok := data[key]; ok {
			valueStr := fmt.Sprint(value)
			name := extractor.Name
			if name == "" {
				name = key
			}
			results[name] = valueStr
		}
	}

	return results
}

// extractJSON extracts data using JSON queries (JQ-style)
func extractJSON(extractor *Extractor, content string) map[string]string {
	results := make(map[string]string)

	var jsonObj interface{}
	if err := json.Unmarshal([]byte(content), &jsonObj); err != nil {
		return results
	}

	for _, compiled := range extractor.jsonCompiled {
		iter := compiled.Run(jsonObj)
		var values []string
		for {
			v, ok := iter.Next()
			if !ok {
				break
			}
			if _, isErr := v.(error); isErr {
				break
			}

			// Convert result to string
			var resultStr string
			if s, ok := v.(string); ok {
				resultStr = s
			} else if b, err := json.Marshal(v); err == nil {
				resultStr = string(b)
			} else {
				resultStr = fmt.Sprint(v)
			}

			if resultStr != "" {
				values = append(values, resultStr)
			}
		}

		if len(values) > 0 {
			name := extractor.Name
			if name == "" {
				name = "extracted"
			}
			results[name] = strings.Join(values, "\n")
		}
	}

	return results
}

// extractXPath extracts data using XPath queries
func extractXPath(extractor *Extractor, content string) map[string]string {
	results := make(map[string]string)

	// Determine if content is XML or HTML
	isXML := strings.HasPrefix(content, "<?xml")

	for _, xpath := range extractor.XPath {
		var values []string

		if isXML {
			doc, err := xmlquery.Parse(strings.NewReader(content))
			if err != nil {
				continue
			}
			nodes, err := xmlquery.QueryAll(doc, xpath)
			if err != nil {
				continue
			}

			for _, node := range nodes {
				var value string
				if extractor.Attr != "" {
					value = node.SelectAttr(extractor.Attr)
				} else {
					value = node.InnerText()
				}
				if value != "" {
					values = append(values, value)
				}
			}
		} else {
			doc, err := htmlquery.Parse(strings.NewReader(content))
			if err != nil {
				continue
			}
			nodes, err := htmlquery.QueryAll(doc, xpath)
			if err != nil {
				continue
			}

			for _, node := range nodes {
				var value string
				if extractor.Attr != "" {
					value = htmlquery.SelectAttr(node, extractor.Attr)
				} else {
					value = htmlquery.InnerText(node)
				}
				if value != "" {
					values = append(values, value)
				}
			}
		}

		if len(values) > 0 {
			name := extractor.Name
			if name == "" {
				name = "extracted"
			}
			results[name] = strings.Join(values, "\n")
		}
	}

	return results
}

// extractDSL extracts data using DSL expressions
func extractDSL(extractor *Extractor, data map[string]interface{}) map[string]string {
	results := make(map[string]string)

	for _, expr := range extractor.dslCompiled {
		result, err := expr.Evaluate(data)
		if err != nil {
			continue
		}

		if result != nil {
			resultStr := fmt.Sprint(result)
			if resultStr != "" {
				name := extractor.Name
				if name == "" {
					name = "extracted"
				}
				results[name] = resultStr
			}
		}
	}

	return results
}

// replaceVariables replaces template variables in the given string
func replaceVariables(input string, variables map[string]interface{}) string {
	result := input

	// First, handle dynamic functions like {{rand_int(min, max)}}
	result = replaceDynamicFunctions(result)

	// Then replace {{variable}} patterns
	for key, value := range variables {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, fmt.Sprint(value))
	}

	return result
}

// replaceDynamicFunctions replaces dynamic function calls in template
func replaceDynamicFunctions(input string) string {
	result := input

	// Replace {{rand_int(min, max)}} with a random integer
	// Simple regex-like replacement for rand_int
	for strings.Contains(result, "{{rand_int(") {
		start := strings.Index(result, "{{rand_int(")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], ")}}")
		if end == -1 {
			break
		}
		end += start + 3 // Include the closing )}}

		// Extract the function call
		funcCall := result[start:end]

		// Parse parameters (simple implementation)
		// Format: {{rand_int(min, max)}}
		paramsStart := strings.Index(funcCall, "(")
		paramsEnd := strings.Index(funcCall, ")")
		if paramsStart != -1 && paramsEnd != -1 {
			params := funcCall[paramsStart+1 : paramsEnd]
			parts := strings.Split(params, ",")
			if len(parts) == 2 {
				// Parse min and max (simple implementation)
				min := 10000
				max := 99999
				if len(strings.TrimSpace(parts[0])) > 0 {
					fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &min)
				}
				if len(strings.TrimSpace(parts[1])) > 0 {
					fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &max)
				}

				// Generate random number between min and max
				rand.Seed(time.Now().UnixNano())
				randomNum := min + rand.Intn(max-min+1)
				result = strings.Replace(result, funcCall, fmt.Sprint(randomNum), 1)
			}
		}
	}

	return result
}

// evaluateDSLExpression evaluates a DSL expression with given data
func evaluateDSLExpression(expression string, data map[string]interface{}) (interface{}, error) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.HelperFunctions())
	if err != nil {
		return nil, err
	}
	return compiled.Evaluate(data)
}

// normalizeToStringSlice converts interface{} to string slice
func normalizeToStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []interface{}:
		var result []string
		for _, item := range val {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}
