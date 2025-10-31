package nuclei

import (
	"embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Parser 模板解析器
type Parser struct {
	templateFS *embed.FS
}

// NewParser 创建新的解析器
func NewParser(templateFS *embed.FS) *Parser {
	return &Parser{
		templateFS: templateFS,
	}
}

// ParseFromEmbed 从嵌入文件系统解析模板
func (p *Parser) ParseFromEmbed(templatePath string) (*Template, error) {
	if p.templateFS == nil {
		return nil, fmt.Errorf("嵌入文件系统未初始化")
	}

	data, err := p.templateFS.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("读取模板文件失败: %v", err)
	}

	return p.parse(data)
}

// ParseFromFile 从文件解析模板
func (p *Parser) ParseFromFile(filePath string) (*Template, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取模板文件失败: %v", err)
	}

	return p.parse(data)
}

// parse 解析YAML数据
func (p *Parser) parse(data []byte) (*Template, error) {
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("解析YAML失败: %v", err)
	}

	// 验证模板
	if err := p.validate(&tmpl); err != nil {
		return nil, err
	}

	return &tmpl, nil
}

// validate 验证模板
func (p *Parser) validate(tmpl *Template) error {
	if tmpl.ID == "" {
		return fmt.Errorf("模板ID不能为空")
	}

	if len(tmpl.HTTP) == 0 {
		return fmt.Errorf("模板必须包含至少一个HTTP请求")
	}

	// 设置默认值
	for i := range tmpl.HTTP {
		if tmpl.HTTP[i].Method == "" {
			tmpl.HTTP[i].Method = "GET"
		}
		if tmpl.HTTP[i].MaxRedirects == 0 {
			tmpl.HTTP[i].MaxRedirects = 10
		}
		if tmpl.HTTP[i].MatchersCondition == "" {
			tmpl.HTTP[i].MatchersCondition = "or"
		}

		// 设置matcher默认part
		for j := range tmpl.HTTP[i].Matchers {
			if tmpl.HTTP[i].Matchers[j].Part == "" {
				tmpl.HTTP[i].Matchers[j].Part = "body"
			}
			if tmpl.HTTP[i].Matchers[j].Condition == "" {
				tmpl.HTTP[i].Matchers[j].Condition = "or"
			}
		}

		// 设置extractor默认part
		for j := range tmpl.HTTP[i].Extractors {
			if tmpl.HTTP[i].Extractors[j].Part == "" {
				tmpl.HTTP[i].Extractors[j].Part = "body"
			}
		}
	}

	return nil
}
