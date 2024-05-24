package vul

import (
	"appsploit/cmd/appsploit/flags"
	"github.com/urfave/cli/v2"
)

func CmdChecksec(v Vulnerability, alias []string) *cli.Command {
	return &cli.Command{
		Name:    v.GetName(),
		Aliases: alias,
		Usage:   v.GetDescription(),
		Flags:   flags.SubCmdFlags,
		Action: func(ctx *cli.Context) (err error) {
			_, err = v.CheckSec(ctx)
			v.GetVulnerabilityExists()
			if err != nil {
				return
			}
			v.Output()
			return
		},
	}
}

func CmdExploit(v Vulnerability, alias []string) *cli.Command {
	return &cli.Command{
		Name:    v.GetName(),
		Aliases: alias,
		Usage:   v.GetDescription(),
		Flags:   flags.SubCmdFlags,
		Action: func(ctx *cli.Context) (err error) {
			_, err = v.Exploit(ctx)
			v.GetVulnerabilityExists()
			if err != nil {
				return
			}
			v.Output()
			return
		},
	}
}

func CmdVul(v Vulnerability, alias []string) *cli.Command {
	checksec := CmdChecksec(v, []string{"c"})
	checksec.Name = "checksec"
	checksec.Usage = "check vulnerability exists"

	exploit := CmdExploit(v, []string{"x"})
	exploit.Name = "exploit"
	exploit.Usage = "run exploit"
	return &cli.Command{
		Name:    v.GetName(),
		Aliases: alias,
		Usage:   v.GetDescription(),
		Subcommands: []*cli.Command{
			checksec,
			exploit,
		},
	}
}
