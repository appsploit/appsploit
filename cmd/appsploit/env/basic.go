package env

import (
	"appsploit/cmd/appsploit/flag"
	"appsploit/env"
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/urfave/cli/v2"
)

var WebServer = &cli.Command{
	Name:    "webserver",
	Aliases: []string{"w"},
	Usage:   "show webserver info",
	Flags:   flag.Flags,
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
	Flags:   flag.Flags,
	Action: func(ctx *cli.Context) (err error) {
		result := env.Framework(ctx)
		fmt.Println(printer.Printer.Print(result))
		return
	},
}
