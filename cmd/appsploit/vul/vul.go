package vul

import (
	"appsploit/pkg/utils/nuclei"
	"appsploit/vul/cve-2024-23334"
	"appsploit/vul/cve-2024-38819"
	"appsploit/vul/cve-2024-38856"
	"appsploit/vul/cve-2024-45216"
	"appsploit/vul/cve-2024-4956"
	"appsploit/vul/cve-2025-27817"

	"github.com/urfave/cli/v2"
)

func init() {
	// 加载内置漏洞命令
	subcommands := []*cli.Command{
		cve_2024_23334.VulCmd,
		cve_2024_38819.VulCmd,
		cve_2024_38856.VulCmd,
		cve_2024_4956.VulCmd,
		cve_2024_45216.VulCmd,
		cve_2025_27817.VulCmd,
	}

	// 动态加载模板命令
	templatesDir, err := nuclei.GetTemplatesDir()
	if err == nil {
		vulCmds, _, _, err := nuclei.LoadTemplateCommands(templatesDir)
		if err == nil && len(vulCmds) > 0 {
			subcommands = append(subcommands, vulCmds...)
		}
	}

	Command.Subcommands = subcommands
}

var Command = &cli.Command{
	Name:    "vul",
	Aliases: []string{"v"},
	Usage:   "list vulnerabilities",
}
