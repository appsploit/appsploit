package checksec

import (
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
		Auto,
		cve_2024_23334.CheckSecCmd,
		cve_2024_38819.CheckSecCmd,
		cve_2024_38856.CheckSecCmd,
		cve_2024_4956.CheckSecCmd,
		cve_2024_45216.CheckSecCmd,
		cve_2025_27817.CheckSecCmd,
	}

	// 动态加载模板命令（模板不生成checksec命令，所以这里不需要加载）
	// templatesDir, err := nuclei.GetTemplatesDir()
	// if err == nil {
	// 	_, checksecCmds, _, err := nuclei.LoadTemplateCommands(templatesDir)
	// 	if err == nil && len(checksecCmds) > 0 {
	// 		subcommands = append(subcommands, checksecCmds...)
	// 	}
	// }

	Command.Subcommands = subcommands
}

var Command = &cli.Command{
	Name:    "checksec",
	Aliases: []string{"c"},
	Usage:   "check security inside a application",
}
