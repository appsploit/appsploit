package env

import (
	"appsploit/cmd/appsploit/flags"
	"appsploit/env"
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/urfave/cli/v2"
)

var WebServer = &cli.Command{
	Name:    "webserver",
	Aliases: []string{"w"},
	Usage:   "show webserver info",
	Flags:   flags.SubCmdFlags,
	Action: func(ctx *cli.Context) (err error) {
		result := env.WebServer(ctx)
		fmt.Println(printer.Printer.Print(result))
		return
	},
}

var Framework = &cli.Command{
	Name:    "framework",
	Aliases: []string{"f"},
	Usage:   "show framework info",
	Flags:   flags.SubCmdFlags,
	Action: func(ctx *cli.Context) (err error) {
		result := env.Framework(ctx)
		fmt.Println(printer.Printer.Print(result))
		return
	},
}
