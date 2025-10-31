package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scanner 模板扫描器
type Scanner struct {
	templatesDir string
	parser       *Parser
}

// NewScanner 创建新的扫描器
func NewScanner(templatesDir string) *Scanner {
	return &Scanner{
		templatesDir: templatesDir,
		parser:       NewParser(nil),
	}
}

// ScanAll 扫描所有模板文件
func (s *Scanner) ScanAll() ([]*TemplateInfo, error) {
	var templates []*TemplateInfo

	// 检查目录是否存在
	if _, err := os.Stat(s.templatesDir); os.IsNotExist(err) {
		return templates, fmt.Errorf("模板目录不存在: %s", s.templatesDir)
	}

	// 递归扫描所有.yaml文件
	err := filepath.Walk(s.templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 只处理.yaml和.yml文件
		if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}

		// 解析模板
		tmpl, err := s.parser.ParseFromFile(path)
		if err != nil {
			// 跳过无法解析的文件
			return nil
		}

		// 提取模板信息
		templateInfo := s.extractTemplateInfo(tmpl, path)
		templates = append(templates, templateInfo)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return templates, nil
}

// ScanByYear 扫描指定年份的模板
func (s *Scanner) ScanByYear(year string) ([]*TemplateInfo, error) {
	yearDir := filepath.Join(s.templatesDir, "cves", year)

	// 检查目录是否存在
	if _, err := os.Stat(yearDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("年份目录不存在: %s", yearDir)
	}

	var templates []*TemplateInfo

	err := filepath.Walk(yearDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}

		tmpl, err := s.parser.ParseFromFile(path)
		if err != nil {
			return nil
		}

		templateInfo := s.extractTemplateInfo(tmpl, path)
		templates = append(templates, templateInfo)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return templates, nil
}

// FindByID 根据ID查找模板
func (s *Scanner) FindByID(id string) (*Template, string, error) {
	var foundPath string
	var foundTemplate *Template

	err := filepath.Walk(s.templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}

		tmpl, err := s.parser.ParseFromFile(path)
		if err != nil {
			return nil
		}

		// 匹配ID（不区分大小写）
		if strings.EqualFold(tmpl.ID, id) {
			foundTemplate = tmpl
			foundPath = path
			return filepath.SkipAll // 找到后停止遍历
		}

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return nil, "", err
	}

	if foundTemplate == nil {
		return nil, "", fmt.Errorf("未找到模板: %s", id)
	}

	return foundTemplate, foundPath, nil
}

// extractTemplateInfo 从模板提取信息
func (s *Scanner) extractTemplateInfo(tmpl *Template, filePath string) *TemplateInfo {
	info := &TemplateInfo{
		ID:          tmpl.ID,
		Name:        tmpl.Info.Name,
		Severity:    tmpl.Info.Severity,
		Description: tmpl.Info.Description,
		FilePath:    filePath,
	}

	// 处理Author（可能是string或[]string）
	if tmpl.Info.Author != nil {
		switch v := tmpl.Info.Author.(type) {
		case string:
			info.Author = []string{v}
		case []interface{}:
			for _, a := range v {
				if str, ok := a.(string); ok {
					info.Author = append(info.Author, str)
				}
			}
		case []string:
			info.Author = v
		}
	}

	// 处理Tags（可能是string或[]string）
	if tmpl.Info.Tags != nil {
		switch v := tmpl.Info.Tags.(type) {
		case string:
			// 按逗号分割
			tags := strings.Split(v, ",")
			for _, tag := range tags {
				info.Tags = append(info.Tags, strings.TrimSpace(tag))
			}
		case []interface{}:
			for _, t := range v {
				if str, ok := t.(string); ok {
					info.Tags = append(info.Tags, str)
				}
			}
		case []string:
			info.Tags = v
		}
	}

	return info
}

// GetExecutablePath 获取可执行文件所在目录
func GetExecutablePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}

// GetTemplatesDir 获取templates目录路径
func GetTemplatesDir() (string, error) {
	exePath, err := GetExecutablePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(exePath, "templates"), nil
}
