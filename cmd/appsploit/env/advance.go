package env

import (
	"appsploit/cmd/appsploit/flags"
	"appsploit/env"
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/urfave/cli/v2"
)

var OS = &cli.Command{
	Name:    "os",
	Aliases: []string{"o"},
	Usage:   "show os info",
	Flags:   flags.SubCmdFlags,
	Action: func(ctx *cli.Context) (err error) {
		result := env.OS(ctx)
		fmt.Println(printer.Printer.Print(result))
		return
	},
}

var Component = &cli.Command{
	Name:    "component",
	Aliases: []string{"c"},
	Usage:   "show component list",
	Flags:   flags.SubCmdFlags,
	Action: func(ctx *cli.Context) (err error) {
		result := env.Component(ctx)
		fmt.Println(printer.Printer.Print(result))
		return
	},
}
