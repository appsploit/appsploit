package nuclei

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// TCPExecutor represents TCP executor
type TCPExecutor struct {
	template        *Template
	host            string
	port            string
	customVariables map[string]interface{}
}

// NewTCPExecutor creates a new TCP executor
func NewTCPExecutor(template *Template, host, port string) *TCPExecutor {
	return &TCPExecutor{
		template:        template,
		host:            host,
		port:            port,
		customVariables: make(map[string]interface{}),
	}
}

// SetCustomVariables sets custom variables that override template variables
func (e *TCPExecutor) SetCustomVariables(vars map[string]interface{}) {
	if e.customVariables == nil {
		e.customVariables = make(map[string]interface{})
	}
	for k, v := range vars {
		e.customVariables[k] = v
	}
}

// Execute executes TCP request
func (e *TCPExecutor) Execute() (*Result, error) {
	result := &Result{
		Vulnerable:       false,
		ExtractedResults: make(map[string]string),
		MatchedData:      []string{},
		TemplateID:       e.template.ID,
		TemplateName:     e.template.Info.Name,
		Severity:         e.template.Info.Severity,
	}

	// 合并tcp和network配置
	tcpRequests := e.template.TCP
	if len(e.template.Network) > 0 {
		tcpRequests = append(tcpRequests, e.template.Network...)
	}

	if len(tcpRequests) == 0 {
		return result, fmt.Errorf("模板中没有TCP请求配置")
	}

	// 遍历所有TCP请求
	for _, tcpReq := range tcpRequests {
		// 遍历所有主机
		hosts := tcpReq.Host
		if len(hosts) == 0 {
			hosts = []string{fmt.Sprintf("%s:%s", e.host, e.port)}
		}

		for _, host := range hosts {
			// 替换变量
			host = e.replaceVariables(host)

			// 执行TCP请求
			tcpResult, err := e.executeTCPRequest(&tcpReq, host)
			if err != nil {
				continue // 继续尝试其他主机
			}

			// 检查matchers
			if e.checkMatchers(&tcpReq, tcpResult) {
				result.Vulnerable = true
				result.MatchedURL = host
				result.Request = tcpResult.Request
				result.Response = tcpResult.Response

				// 提取数据
				if len(tcpReq.Extractors) > 0 {
					extracted := e.extractData(&tcpReq, tcpResult)
					for k, v := range extracted {
						result.ExtractedResults[k] = v
					}
				}

				return result, nil
			}
		}
	}

	return result, nil
}

// TCPResult represents TCP request result
type TCPResult struct {
	Response string
	Request  string
}

// executeTCPRequest executes a single TCP request
func (e *TCPExecutor) executeTCPRequest(tcpReq *TCP, host string) (*TCPResult, error) {
	// 连接超时5秒
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	result := &TCPResult{}
	var allRequests strings.Builder
	var allResponses strings.Builder

	// 处理inputs
	for _, input := range tcpReq.Inputs {
		var data []byte

		// 根据type处理数据
		switch strings.ToLower(input.Type) {
		case "hex":
			// 十六进制数据
			data, err = hex.DecodeString(strings.ReplaceAll(input.Data, " ", ""))
			if err != nil {
				return nil, fmt.Errorf("解析十六进制数据失败: %v", err)
			}
		default:
			// 文本数据（默认）
			data = []byte(e.replaceVariables(input.Data))
		}

		// 发送数据
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}

		allRequests.WriteString(string(data))

		// 读取响应
		if input.Read > 0 {
			buf := make([]byte, input.Read)
			n, err := conn.Read(buf)
			if err != nil && err.Error() != "EOF" {
				return nil, err
			}
			allResponses.Write(buf[:n])
		}
	}

	// 如果设置了read-all或没有指定read大小，则读取所有数据
	if tcpReq.ReadAll {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				allResponses.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	} else if tcpReq.ReadSize > 0 {
		buf := make([]byte, tcpReq.ReadSize)
		n, _ := conn.Read(buf)
		allResponses.Write(buf[:n])
	}

	result.Request = allRequests.String()
	result.Response = allResponses.String()

	return result, nil
}

// checkMatchers 检查TCP matchers
func (e *TCPExecutor) checkMatchers(tcpReq *TCP, result *TCPResult) bool {
	if len(tcpReq.Matchers) == 0 {
		return true
	}

	matchersCondition := strings.ToLower(tcpReq.MatchersCondition)
	if matchersCondition == "" {
		matchersCondition = "or"
	}

	matched := false

	for _, matcher := range tcpReq.Matchers {
		matchResult := e.checkMatcher(&matcher, result)

		if matcher.Negative {
			matchResult = !matchResult
		}

		if matchersCondition == "and" {
			if !matchResult {
				return false
			}
			matched = true
		} else {
			if matchResult {
				matched = true
				break
			}
		}
	}

	return matched
}

// checkMatcher checks a single matcher
func (e *TCPExecutor) checkMatcher(matcher *Matcher, result *TCPResult) bool {
	content := result.Response

	switch strings.ToLower(matcher.Type) {
	case "word", "words":
		return matchWords(matcher.Words, content, matcher.Condition, matcher.CaseInsensitive)
	case "regex":
		return matchRegex(matcher.regexCompiled, content, matcher.Condition)
	case "binary":
		return matchBinary(matcher.Binary, []byte(content))
	default:
		return false
	}
}

// extractData extracts TCP data
func (e *TCPExecutor) extractData(tcpReq *TCP, result *TCPResult) map[string]string {
	extracted := make(map[string]string)
	data := make(map[string]interface{})

	for _, extractor := range tcpReq.Extractors {
		content := result.Response
		extractorResults := extractFromContent(&extractor, content, data)
		for k, v := range extractorResults {
			extracted[k] = v
		}
	}

	return extracted
}

// replaceVariables replaces variables
func (e *TCPExecutor) replaceVariables(input string) string {
	result := strings.ReplaceAll(input, "{{Hostname}}", e.host)
	result = strings.ReplaceAll(result, "{{Host}}", e.host)
	result = strings.ReplaceAll(result, "{{Port}}", e.port)

	// Replace template variables
	for k, v := range e.template.Variables {
		placeholder := fmt.Sprintf("{{%s}}", k)
		if strVal, ok := v.(string); ok {
			result = strings.ReplaceAll(result, placeholder, strVal)
		} else {
			result = strings.ReplaceAll(result, placeholder, fmt.Sprint(v))
		}
	}

	// Replace custom variables (highest priority)
	for k, v := range e.customVariables {
		placeholder := fmt.Sprintf("{{%s}}", k)
		if strVal, ok := v.(string); ok {
			result = strings.ReplaceAll(result, placeholder, strVal)
		} else {
			result = strings.ReplaceAll(result, placeholder, fmt.Sprint(v))
		}
	}

	return result
}

// matchBinary matches binary data
func matchBinary(patterns []string, content []byte) bool {
	for _, pattern := range patterns {
		// 移除空格
		pattern = strings.ReplaceAll(pattern, " ", "")
		data, err := hex.DecodeString(pattern)
		if err != nil {
			continue
		}

		// 简单的字节匹配
		if strings.Contains(string(content), string(data)) {
			return true
		}
	}
	return false
}
