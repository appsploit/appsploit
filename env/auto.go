package env

import (
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/urfave/cli/v2"
)

type Result map[string]printer.Interface

func Auto(ctx *cli.Context) {
	result := Result{
		"webserver":      WebServer(ctx),
		"framework":      Framework(ctx),
		"os":             OS(ctx),
		"component_list": Component(ctx),
	}
	fmt.Println(printer.Printer.Print(result))
}
