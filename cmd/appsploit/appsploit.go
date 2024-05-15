package main

import (
	"appsploit/cmd/appsploit/auto"
	"appsploit/cmd/appsploit/checksec"
	"appsploit/cmd/appsploit/env"
	"appsploit/cmd/appsploit/exploit"
	"appsploit/cmd/appsploit/flags"
	"appsploit/cmd/appsploit/upload"
	"appsploit/cmd/appsploit/vul"
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/app"
	"github.com/ctrsploit/sploit-spec/pkg/version"
	"github.com/urfave/cli/v2"
	"os"
)

const usage = `An example sploit tool follows sploit-spec`

func init() {
	version.ProductName = "appsploit"
}

func main() {
	sploit := &cli.App{
		Name:  "appsploit",
		Usage: usage,
		Flags: flags.AppCmdFlags,
		Commands: []*cli.Command{
			auto.Command,
			env.Command,
			upload.Command,
			checksec.Command,
			exploit.Command,
			vul.Command,
			version.Command,
		},
	}
	app.InstallGlobalFlags(sploit)
	err := sploit.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
