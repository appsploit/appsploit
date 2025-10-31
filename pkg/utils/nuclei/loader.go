package nuclei

import (
	"appsploit/cmd/appsploit/flags"
	"fmt"
	"strings"

	"github.com/ctrsploit/sploit-spec/pkg/app"
	"github.com/ctrsploit/sploit-spec/pkg/exeenv"
	"github.com/ctrsploit/sploit-spec/pkg/vul"
	"github.com/urfave/cli/v2"
)

// TemplateVulnerability 模板漏洞包装器
type TemplateVulnerability struct {
	vul.BaseVulnerability
	template     *Template
	templatePath string
	parser       *Parser
}

// LoadTemplateCommands 加载所有模板命令
func LoadTemplateCommands(templatesDir string) ([]*cli.Command, []*cli.Command, []*cli.Command, error) {
	scanner := NewScanner(templatesDir)
	templates, err := scanner.ScanAll()
	if err != nil {
		// 如果扫描失败，返回空列表而不是错误（允许没有templates目录）
		return nil, nil, nil, nil
	}

	var vulCmds []*cli.Command
	var checksecCmds []*cli.Command
	var exploitCmds []*cli.Command

	for _, tmplInfo := range templates {
		// 为每个模板创建命令
		vulCmd, checksecCmd, exploitCmd := createTemplateCommands(tmplInfo)
		vulCmds = append(vulCmds, vulCmd)
		checksecCmds = append(checksecCmds, checksecCmd)
		exploitCmds = append(exploitCmds, exploitCmd)
	}

	return vulCmds, checksecCmds, exploitCmds, nil
}

// createTemplateCommands 为单个模板创建命令
func createTemplateCommands(tmplInfo *TemplateInfo) (*cli.Command, *cli.Command, *cli.Command) {
	// 生成唯一的Name（添加tpl-前缀）
	uniqueName := "tpl-" + tmplInfo.ID

	// 创建漏洞实例
	templateVul := &TemplateVulnerability{
		BaseVulnerability: vul.BaseVulnerability{
			Name:        uniqueName,
			Description: tmplInfo.Name, // 只显示漏洞名称
			Level:       severityToLevel(tmplInfo.Severity),
			ExeEnv: exeenv.ExeEnv{
				Env:     exeenv.Remote,
				Check:   exeenv.Remote,
				Exploit: exeenv.Remote,
			},
		},
		templatePath: tmplInfo.FilePath,
		parser:       NewParser(nil),
	}

	// 生成别名
	aliases := generateAliases(tmplInfo.ID)

	// 创建命令
	// 模板漏洞不生成checksec命令，只生成vul和exploit命令
	vulCmd := app.Vul2VulCmd(templateVul, aliases, nil, nil, true)
	exploitCmd := app.Vul2ExploitCmd(templateVul, aliases, flags.SubCmdFlags, true)

	// 返回nil作为checksecCmd，表示不生成checksec命令
	return vulCmd, nil, exploitCmd
}

// CheckSec implements vulnerability detection
func (t *TemplateVulnerability) CheckSec(context *cli.Context) (vulnerabilityExists bool, err error) {
	// Parse template
	if t.template == nil {
		tmpl, err := t.parser.ParseFromFile(t.templatePath)
		if err != nil {
			return false, fmt.Errorf("failed to parse template: %v", err)
		}
		t.template = tmpl
	}

	// Parse custom variables from custom-data parameter
	customVars := parseCustomData(context.String("custom-data"))

	// Execute based on template type
	var result *Result

	if len(t.template.HTTP) > 0 {
		// HTTP template
		baseURL := getTargetURL(context)
		if baseURL == "" {
			return false, fmt.Errorf("HTTP template requires URL parameter (--url or --target)")
		}

		executor := NewExecutor(t.template, baseURL)
		executor.SetCustomVariables(customVars)
		result, err = executor.Execute()
	} else if len(t.template.TCP) > 0 || len(t.template.Network) > 0 {
		// TCP template
		host, port := getTargetHost(context)
		if host == "" {
			return false, fmt.Errorf("TCP template requires target host (--host or --target)")
		}

		executor := NewTCPExecutor(t.template, host, port)
		executor.SetCustomVariables(customVars)
		result, err = executor.Execute()
	} else {
		return false, fmt.Errorf("unsupported template type")
	}

	if err != nil {
		return false, err
	}

	t.VulnerabilityExists = result.Vulnerable

	return t.BaseVulnerability.CheckSec(context)
}

// Exploit implements vulnerability exploitation
func (t *TemplateVulnerability) Exploit(context *cli.Context) error {
	// Parse template if not already parsed
	if t.template == nil {
		tmpl, err := t.parser.ParseFromFile(t.templatePath)
		if err != nil {
			return fmt.Errorf("failed to parse template: %v", err)
		}
		t.template = tmpl
	}

	// Parse custom variables from custom-data parameter
	customVars := parseCustomData(context.String("custom-data"))

	// Execute template directly without CheckSec
	var result *Result
	var err error

	if len(t.template.HTTP) > 0 {
		baseURL := getTargetURL(context)
		if baseURL == "" {
			return fmt.Errorf("HTTP template requires URL parameter (--url or --target)")
		}
		executor := NewExecutor(t.template, baseURL)
		executor.SetCustomVariables(customVars)
		result, err = executor.Execute()
	} else if len(t.template.TCP) > 0 || len(t.template.Network) > 0 {
		host, port := getTargetHost(context)
		if host == "" {
			return fmt.Errorf("TCP template requires target host (--host or --target)")
		}
		executor := NewTCPExecutor(t.template, host, port)
		executor.SetCustomVariables(customVars)
		result, err = executor.Execute()
	} else {
		return fmt.Errorf("unsupported template type")
	}

	if err != nil {
		return err
	}

	// Set vulnerability status based on result
	t.VulnerabilityExists = result.Vulnerable

	// Format result
	output := formatTemplateResult(result)
	t.VulnerabilityResponse = output

	// Use BaseVulnerability output method
	t.BaseVulnerability.OutputResp()

	return nil
}

// parseCustomData parses custom-data parameter into key-value map
// Format: key1=value1,key2=value2
func parseCustomData(customData string) map[string]interface{} {
	variables := make(map[string]interface{})
	if customData == "" {
		return variables
	}

	// Split by comma
	pairs := strings.Split(customData, ",")
	for _, pair := range pairs {
		// Split by equals sign
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			if key != "" {
				variables[key] = value
			}
		}
	}

	return variables
}

// getTargetURL 从context获取目标URL
func getTargetURL(context *cli.Context) string {
	// 优先使用url参数
	if urlStr := context.String("url"); urlStr != "" {
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			urlStr = "http://" + urlStr
		}
		return strings.TrimRight(urlStr, "/")
	}

	// 回退到target/port/tls
	target := context.String("target")
	if target == "" {
		return ""
	}

	proto := "http"
	if context.Bool("tls") {
		proto = "https"
	}
	port := context.Int("port")
	if port == 0 {
		port = 80
	}

	return fmt.Sprintf("%s://%s:%d", proto, target, port)
}

// getTargetHost 从context获取目标主机和端口
func getTargetHost(context *cli.Context) (string, string) {
	host := context.String("host")
	if host == "" {
		host = context.String("target")
	}

	port := fmt.Sprintf("%d", context.Int("port"))
	if port == "0" {
		port = "80"
	}

	return host, port
}

// generateAliases 生成命令别名
func generateAliases(id string) []string {
	// 将ID转换为小写并替换-为_，添加tpl_前缀避免与内置漏洞冲突
	alias := "tpl_" + strings.ToLower(strings.ReplaceAll(id, "-", "_"))
	return []string{alias}
}

// severityToLevel 将严重程度转换为vul.Level
func severityToLevel(severity string) vul.Level {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return vul.LevelHigh
	case "medium":
		return vul.LevelMedium
	case "low", "info":
		return vul.LevelLow
	default:
		return vul.LevelLow
	}
}

// formatTemplateResult formats template execution result
func formatTemplateResult(result *Result) string {
	var output strings.Builder

	// Only show extracted data and response, no vulnerability info
	if len(result.ExtractedResults) > 0 {
		output.WriteString("Extracted Data:\n")
		for name, value := range result.ExtractedResults {
			output.WriteString(fmt.Sprintf("  %s:\n%s\n", name, value))
		}
		output.WriteString("\n")
	}

	if result.Response != "" {
		// Show full response without truncation
		output.WriteString(result.Response)
	}

	return output.String()
}
