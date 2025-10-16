package vul

import (
	"appsploit/vul/cve-2024-23334"

	"github.com/urfave/cli/v2"
)

var Command = &cli.Command{
	Name:    "vul",
	Aliases: []string{"v"},
	Usage:   "list vulnerabilities",
	Subcommands: []*cli.Command{
		cve_2024_23334.VulCmd,
	},
}
