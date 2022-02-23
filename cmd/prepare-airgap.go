package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"kore-on/pkg/conf"
	"kore-on/pkg/model"
	"kore-on/pkg/utils"
	"log"
	"os"
	"syscall"
	"time"
)

type strPrepareAirgapCmd struct {
	name    string
	dryRun  bool
	timeout int64
	target  string
	verbose bool
	step    bool
}

func prepareAirgapCmd() *cobra.Command {
	airgap := &strPrepareAirgapCmd{}
	cmd := &cobra.Command{
		Use:          "prepare-airgap [flags]",
		Short:        "prepare-airgap",
		Long:         "",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return airgap.run()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&airgap.target, "target", "", "", "target module. [registry|liteedge-master|liteedge-worker]")
	f.BoolVarP(&airgap.verbose, "verbose", "v", false, "verbose")
	f.BoolVarP(&airgap.step, "step", "", false, "step")
	f.BoolVarP(&airgap.dryRun, "dry-run", "d", false, "dryRun")
	return cmd
}

func (c *strPrepareAirgapCmd) run() error {
	workDir, _ := os.Getwd()
	var err error = nil
	koreonToml, _ := utils.ValidateKoreonTomlConfig(workDir)
	startTime := time.Now()
	logger.Infof("Start provisioning for cloud infrastructure [%s]", koreonToml.NodePool.Provider)

	switch c.target {
	default:
		utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "\nDestroy koreon cluster ..."))
		if err = c.prepareAirgap(workDir, koreonToml); err != nil {
			return err
		}
		utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, fmt.Sprintf("Setup cube cluster Done. (%v)", (time.Duration(time.Since(startTime).Seconds())*time.Second).String())))
	}

	//infra.PrintK8sWorkResult(workDir, c.target)
	utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "Installation Completed."))
	return nil
}

func (c *strPrepareAirgapCmd) prepareAirgap(workDir string, koreonToml model.KoreonToml) error {
	// # 1
	utils.CheckDocker()

	if koreonToml.Koreon.Version != "" {
		utils.CopyFilePreWork(workDir, koreonToml, "destroy")
	}

	inventoryFilePath := utils.CreateInventoryFile(workDir, koreonToml, nil)

	basicFilePath := utils.CreateBasicYaml(workDir, koreonToml)

	commandArgs := []string{
		"docker",
		"run",
		"--name",
		conf.KoreonImageName,
		"--rm",
		"--privileged",
		"-it",
	}

	commandArgsVol := []string{
		"-v",
		fmt.Sprintf("%s:/knit/work", workDir),
		"-v",
		fmt.Sprintf("%s:/knit/inventory/sample/inventory.ini", inventoryFilePath),
		"-v",
		fmt.Sprintf("%s:/knit/inventory/sample/group_vars/all/basic.yml", basicFilePath),
	}

	commandArgsAnsible := []string{
		conf.KoreonImage,
		"ansible-playbook",
		"-i",
		conf.InventoryIni,
		"-u",
		koreonToml.NodePool.Security.SSHUserID, //수정
		"--private-key",
		conf.KoreonDestDir + "/id_rsa",
		conf.PrepareAirgapYaml,
	}

	commandArgs = append(commandArgs, commandArgsVol...)
	commandArgs = append(commandArgs, commandArgsAnsible...)

	//fmt.Printf("%s \n", commandArgs)

	if c.verbose {
		commandArgs = append(commandArgs, "-v")
	}

	if c.step {
		commandArgs = append(commandArgs, "--step")
	}

	if c.dryRun {
		commandArgs = append(commandArgs, "-C")
		commandArgs = append(commandArgs, "-D")
	}

	//log.Printf("Running command and waiting for it to finish...")

	err := syscall.Exec("/usr/local/bin/docker", commandArgs, os.Environ())
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	}

	return nil
}
