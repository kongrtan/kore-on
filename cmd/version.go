package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"kore-on/pkg/conf"
	"runtime"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of EdgeCube",
	Long:  `All software has versions. This is EdgeCube's`,
	Run: func(cmd *cobra.Command, args []string) {
		//fmt.Printf("cube version %s %s/%s\n", conf.CubeSvcVersion, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("edge-cube v%s GitCommit:%s BuildDate:%s Platform:%s/%s\n", conf.Version, conf.CommitId, conf.BuildDate, runtime.GOOS, runtime.GOARCH)
	},
}
