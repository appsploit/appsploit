package env

import (
	"github.com/urfave/cli/v2"
	"testing"
)

func TestWebServer(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "target",
				Value: "www.baidu.com",
			},
			&cli.StringFlag{
				Name:  "port",
				Value: "443",
			},
			&cli.BoolFlag{
				Name:  "https",
				Value: true,
			},
		},
		Action: func(ctx *cli.Context) (err error) {
			t.Log(WebServer(ctx))
			return
		},
	}
	_ = app.Run([]string{})
}

func TestFramework(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "target",
				Value: "www.baidu.com",
			},
			&cli.StringFlag{
				Name:  "port",
				Value: "443",
			},
			&cli.BoolFlag{
				Name:  "https",
				Value: true,
			},
		},
		Action: func(ctx *cli.Context) (err error) {
			t.Log(Framework(ctx))
			return
		},
	}
	_ = app.Run([]string{})
}
