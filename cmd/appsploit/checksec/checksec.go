package checksec

import (
	"appsploit/vul"
	"github.com/ctrsploit/sploit-spec/pkg/app"
	"github.com/urfave/cli/v2"
)

var Command = &cli.Command{
	Name:    "checksec",
	Aliases: []string{"c"},
	Usage:   "check security inside a application",
	Subcommands: []*cli.Command{
		Auto,
		app.Vul2ChecksecCmd(vul.CVE_2099_9999_v1, []string{"2099"}),
	},
}
