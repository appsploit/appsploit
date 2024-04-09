package flag

import (
	"fmt"
	"github.com/urfave/cli/v2"
)

var Flags = []cli.Flag{
	&cli.StringFlag{
		Name:     "target",
		Usage:    "target host/ip",
		Aliases:  []string{"t"},
		Required: true,
	},
	&cli.IntFlag{
		Name:     "port",
		Usage:    "target port",
		Aliases:  []string{"p"},
		Required: true,
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
