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
		Name:    "url",
		Usage:   "target url (e.g., http://example.com:8080)",
		Aliases: []string{"u"},
	},
	&cli.StringFlag{
		Name:    "target",
		Usage:   "target host/ip (for non-HTTP exploits)",
		Aliases: []string{"t"},
	},
	&cli.IntFlag{
		Name:    "port",
		Usage:   "target port (for non-HTTP exploits)",
		Aliases: []string{"p"},
		Value:   80,
		Action: func(context *cli.Context, i int) error {
			if i <= 0 || i > 65535 {
				return fmt.Errorf("target port value %v out of range[1-65535]", i)
			}
			return nil
		},
	},
	&cli.BoolFlag{
		Name:    "tls",
		Usage:   "use https/tls (for non-HTTP exploits)",
		Aliases: []string{"s"},
		Value:   false,
	},
	&cli.StringFlag{
		Name:    "file",
		Usage:   "read filename",
		Aliases: []string{"f"},
	},
	&cli.StringFlag{
		Name:    "path",
		Usage:   "url path",
		Aliases: []string{"P"},
	},
	&cli.StringFlag{
		Name:    "command",
		Usage:   "execute command",
		Aliases: []string{"c"},
	},
	&cli.StringFlag{
		Name:    "custom-data",
		Usage:   "custom data in key=value format, multiple values separated by comma (e.g., broker=kafka:9092,timeout=30)",
		Aliases: []string{"cd"},
	},
	&cli.StringFlag{
		Name:    "template",
		Usage:   "use external nuclei template file",
		Aliases: []string{"T"},
	},
}
