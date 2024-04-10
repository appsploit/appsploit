package flags

import (
	"appsploit/internal/global"
	"fmt"
	"github.com/urfave/cli/v2"
)

var AppCmdFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "proxy",
		Usage: "set proxy",
		Action: func(ctx *cli.Context, value string) error {
			global.HttpProxy = value
			return nil
		},
	},
	&cli.IntFlag{
		Name:  "timeout",
		Usage: "set http timeout",
		Value: 15,
		Action: func(ctx *cli.Context, value int) error {
			global.HttpTimeout = value
			return nil
		},
	},
}

var SubCmdFlags = []cli.Flag{
	&cli.StringFlag{
		Name:     "target",
		Usage:    "target host/ip",
		Aliases:  []string{"t"},
		Required: true,
	},
	&cli.IntFlag{
		Name:    "port",
		Usage:   "target port",
		Aliases: []string{"p"},
		Value:   80,
		Action: func(context *cli.Context, i int) error {
			if i <= 0 && i > 65535 {
				return fmt.Errorf("target port value %v out of range[1-65535]", i)
			}
			return nil
		},
	},
	&cli.BoolFlag{
		Name:    "https",
		Usage:   "https",
		Aliases: []string{"s"},
		Value:   false,
	},
}
