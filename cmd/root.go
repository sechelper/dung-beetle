package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
)

const VERSION = "1.0.1"

var rootCmd *cobra.Command

func init() {

}

func Execute() {

	rootCmd = &cobra.Command{
		Use:     "dung-beetle",
		Version: VERSION,
		Short:   "屎壳郎网络安全审计系统",
		Long: fmt.Sprintf("屎壳郎网络安全审计系统，一款复杂有效的应急工具，" +
			"在原始数据中自动寻找蛛丝马迹."),
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(runCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}

}
