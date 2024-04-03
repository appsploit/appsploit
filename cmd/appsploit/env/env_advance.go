package env

import (
	"appsploit/env"
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/log"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/urfave/cli/v2"
)

var OS = &cli.Command{
	Name:    "os",
	Aliases: []string{"o"},
	Usage:   "show os info",
	Action: func(context *cli.Context) (err error) {
		log.Logger.Debug("")
		result := env.OS()
		fmt.Println(printer.Printer.Print(result))
		return
	},
}

var Component = &cli.Command{
	Name:    "component",
	Aliases: []string{"c"},
	Usage:   "show component list",
	Action: func(context *cli.Context) (err error) {
		log.Logger.Debug("")
		result := env.Component()
		fmt.Println(printer.Printer.Print(result))
		return
	},
}
