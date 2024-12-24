package checksec

import (
	appVul "appsploit/pkg/vul"
	"appsploit/vul"
	"github.com/urfave/cli/v2"
)

var Command = &cli.Command{
	Name:    "checksec",
	Aliases: []string{"c"},
	Usage:   "check security inside a application",
	Subcommands: []*cli.Command{
		Auto,
		appVul.CmdChecksec(&vul.CVE_2024_23334_v1, []string{"2024-23334"}),
		appVul.CmdChecksec(&vul.CVE_2024_45216_v1, []string{"2024-45216"}),
		appVul.CmdChecksec(&vul.CVE_2024_4956_v1, []string{"2024-4956"}),
		appVul.CmdChecksec(&vul.CVE_2024_38819_v1, []string{"2024-38819"}),
		appVul.CmdChecksec(&vul.CVE_2024_38856_v1, []string{"2024-38856"}),
	},
}
