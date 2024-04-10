package env

import (
	"appsploit/cmd/appsploit/flags"
	"appsploit/env"
	"github.com/urfave/cli/v2"
)

const (
	CommandNameAuto = "auto"
)

var (
	Auto = &cli.Command{
		Name:  CommandNameAuto,
		Usage: "auto",
		Flags: flags.SubCmdFlags,
		Action: func(ctx *cli.Context) (err error) {
			env.Auto(ctx)
			return
		},
	}
)
