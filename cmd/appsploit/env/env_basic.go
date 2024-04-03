package env

import (
	"appsploit/env"
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/log"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/urfave/cli/v2"
)

var WebServer = &cli.Command{
	Name:    "webserver",
	Aliases: []string{"w"},
	Usage:   "show webserver info",
	Action: func(context *cli.Context) (err error) {
		log.Logger.Debug("")
		result := env.WebServer()
		fmt.Println(printer.Printer.Print(result))
		return
	},
}

var Framework = &cli.Command{
	Name:    "framework",
	Aliases: []string{"f"},
	Usage:   "show framework info",
	Action: func(context *cli.Context) (err error) {
		log.Logger.Debug("")
		result := env.Framework()
		fmt.Println(printer.Printer.Print(result))
		return
	},
}
