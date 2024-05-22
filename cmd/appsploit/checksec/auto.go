package checksec

import (
	appVul "appsploit/pkg/vul"
	"appsploit/vul"

	"github.com/urfave/cli/v2"
)

const (
	CommandNameAuto = "auto"
)

var (
	Auto = &cli.Command{
		Name:    CommandNameAuto,
		Usage:   "auto",
		Aliases: []string{"a"},
		Action: func(ctx *cli.Context) (err error) {
			vulnerabilities := appVul.Vulnerabilities{
				&vul.CVE_2024_23334_v1,
			}
			err = vulnerabilities.Check(ctx)
			if err != nil {
				return
			}
			vulnerabilities.Output()
			return
		},
	}
)
