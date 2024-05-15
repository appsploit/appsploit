package env

import (
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/ctrsploit/sploit-spec/pkg/result/item"
	"github.com/urfave/cli/v2"
)

func OS(ctx *cli.Context) (result printer.Interface) {
	result = item.Short{
		Name:        "os",
		Description: "OS info",
		Result:      "",
	}
	return result
}

func Component(ctx *cli.Context) (result printer.Interface) {
	result = item.List{
		Name:        "component",
		Description: "component list",
		Result:      []string{},
	}
	return result
}
