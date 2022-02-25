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

type strCreateCmd struct {
	name    string
	dryRun  bool
	timeout int64
	target  string
	verbose bool
	step    bool
}

const initDesc = `
This command get cube script files which used to infra creation. 
`

const createDesc = `
Provision private/public infrastructure and deploy kubernetes cluster, at once run 'create' command. 
Or if want to setup infrastructure and Kubernetes separately, run 'create --target=infra' or 'create --target=k8s' each.
`

const createExample = `
# Create a infra and deploy kubernetes.
cube create

# Create a infra only.
cube create -t infra

# Create kubernetes cluster. Infra should be created before.
cube create -t k8s
`

func createCmd() *cobra.Command {
	create := &strCreateCmd{}

	cmd := &cobra.Command{
		Use:          "create [flags]",
		Short:        "Install kubernetes cluster, registry",
		Long:         initDesc,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return create.run()
		},
	}

	f := cmd.Flags()
	f.StringVarP(&create.target, "target", "", "", "target module. [registry|liteedge-master|liteedge-worker]")
	f.BoolVarP(&create.verbose, "verbose", "v", false, "verbose")
	f.BoolVarP(&create.step, "step", "", false, "step")
	f.BoolVarP(&create.dryRun, "dry-run", "d", false, "dryRun")

	return cmd
}

func (c *strCreateCmd) run() error {

	if !utils.CheckUserInput("Do you really want to create? Only 'yes' will be accepted to confirm: ", "yes") {
		fmt.Println("nothing to changed. exit")
		os.Exit(1)
	}

	workDir, _ := os.Getwd()
	var err error = nil
	koreonToml, _ := utils.ValidateKoreonTomlConfig(workDir)
	startTime := time.Now()
	logger.Infof("Start provisioning for cloud infrastructure [%s]", koreonToml.NodePool.Provider)

	switch c.target {
	default:
		utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "\nSetup cube cluster ..."))
		if err = c.create(workDir, koreonToml); err != nil {
			return err
		}
		utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, fmt.Sprintf("Setup cube cluster Done. (%v)", (time.Duration(time.Since(startTime).Seconds())*time.Second).String())))
	}

	//infra.PrintK8sWorkResult(workDir, c.target)
	utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "Installation Completed."))
	return nil
}

var Version = "unknown_version"
var CommitId = "unknown_commitid"
var BuildDate = "unknown_builddate"

func (c *strCreateCmd) create(workDir string, knitToml model.KoreonToml) error {
	// # 1
	utils.CheckDocker()

	if knitToml.Koreon.Version != "" {
		utils.CopyFilePreWork(workDir, knitToml, "create")
	}

	inventoryFilePath := utils.CreateInventoryFile(workDir, knitToml, nil)

	basicFilePath := utils.CreateBasicYaml(workDir, knitToml, conf.CMD_CREATE)

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
		fmt.Sprintf("%s:%s", workDir, conf.WorkDir),
		"-v",
		fmt.Sprintf("%s:%s", workDir+"/"+conf.KoreonDestDir, conf.Inventory+"/"+conf.KoreonDestDir),
		"-v",
		fmt.Sprintf("%s:%s", inventoryFilePath, conf.InventoryIni),
		"-v",
		fmt.Sprintf("%s:%s", basicFilePath, conf.BasicYaml),
	}

	commandArgsAnsible := []string{
		conf.KoreonImage,
		"ansible-playbook",
		"-i",
		conf.InventoryIni,
		"-u",
		knitToml.NodePool.Security.SSHUserID, //수정
		"--private-key",
		conf.KoreonDestDir + "/id_rsa",
		conf.CreateYaml,
	}

	commandArgs = append(commandArgs, commandArgsVol...)
	commandArgs = append(commandArgs, commandArgsAnsible...)

	fmt.Printf("%s \n", commandArgs)

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
