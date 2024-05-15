package vul

import (
	appVul "appsploit/pkg/vul"
	"appsploit/vul"
	"github.com/urfave/cli/v2"
)

var Command = &cli.Command{
	Name:    "vul",
	Aliases: []string{"v"},
	Usage:   "list vulnerabilities",
	Subcommands: []*cli.Command{
		appVul.CmdVul(vul.CVE_2024_23334_v1, []string{"2024-23334"}),
	},
}
