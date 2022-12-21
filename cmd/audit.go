package cmd

import (
	"dung-beetle/audit/linux"
	"dung-beetle/core"
	"github.com/spf13/cobra"
	"log"
	"regexp"
	"runtime"
)

var runCmd *cobra.Command

func ipAddress(text string) string {
	var rgx = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

	rs := rgx.FindStringSubmatch(text)

	if len(rs) > 0 {
		return rs[0]
	}

	return ""
}

func init() {
	runCmd = &cobra.Command{
		Use:   "audit",
		Short: "审计系统基线",
		Long:  `根据配置的安全基线文件，逐个检查后输出想要的结果`,
		Run: func(cmd *cobra.Command, args []string) {
			switch runtime.GOOS {
			case core.Windows:
				{

				}
			case core.Linux:
				{
					authAudit := linux.NewDefaultAuthAudit()
					result, err := authAudit.Start()
					if err != nil {
						log.Fatal(err)
					}
					authAudit.Report(result)

					userAudit := linux.NewUserDefaultAuditors()
					userAuditResult, _ := userAudit.Start()
					userAudit.Report(userAuditResult)
				}

			}
		},
	}
}
