package cmd

import (
	"github.com/spf13/cobra"
)

type strDestroyCmd struct {
	name    string
	dryRun  bool
	timeout int64
	target  string
	verbose bool
	fast    bool
}

func destroyCmd() *cobra.Command {
	create := &strInitCmd{}
	cmd := &cobra.Command{
		Use:          "destroy [flags]",
		Short:        "destroy",
		Long:         "",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return create.run()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&create.target, "target", "", "", "target module. [registry|liteedge-master|liteedge-worker]")
	f.BoolVarP(&create.verbose, "verbose", "v", false, "verbose")
	f.BoolVarP(&create.fast, "fast", "f", false, "fast")
	f.BoolVarP(&create.dryRun, "dry-run", "d", false, "dryRun")
	return cmd
}

func (c *strDestroyCmd) run() error {
	//workDir, _ := os.Getwd()
	//var err error = nil
	//cubeToml, _ := utils.ValidateCubeTomlConfig(workDir)
	//startTime := time.Now()
	//logger.Infof("Start provisioning for cloud infrastructure [%s]", cubeToml.NodePool.Provider)
	//
	//switch c.target {
	//default:
	//	utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "\nSetup cube cluster ..."))
	//	if err = c.createKubernetes(workDir, cubeToml); err != nil {
	//		return err
	//	}
	//	utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, fmt.Sprintf("Setup cube cluster Done. (%v)", (time.Duration(time.Since(startTime).Seconds())*time.Second).String())))
	//}
	//
	//infra.PrintK8sWorkResult(workDir, c.target)
	//utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "Installation Completed."))
	return nil
}
