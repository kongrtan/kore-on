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
	fast    bool
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
	f.BoolVarP(&create.fast, "fast", "f", false, "fast")
	f.BoolVarP(&create.dryRun, "dry-run", "d", false, "dryRun")

	return cmd
}

func (c *strCreateCmd) run() error {
	workDir, _ := os.Getwd()
	var err error = nil
	cubeToml, _ := utils.ValidateCubeTomlConfig(workDir)
	startTime := time.Now()
	logger.Infof("Start provisioning for cloud infrastructure [%s]", cubeToml.NodePool.Provider)

	switch c.target {
	default:
		utils.PrintInfo(fmt.Sprintf(conf.SUCCESS_FORMAT, "\nSetup cube cluster ..."))
		if err = c.create(workDir, cubeToml); err != nil {
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

func (c *strCreateCmd) create(workDir string, cubeToml model.CubeToml) error {
	// # 1
	utils.CheckDocker()
	//utils.CreateInventoryFile(target, workDir, parentDir+"/cubescripts/inventories") //create inventory
	utils.CreateInventoryFile(workDir, cubeToml)
	utils.CreateBasicYaml(workDir, cubeToml)

	utils.CreateExpertYaml(workDir, cubeToml)
	return nil
}

func (c *strCreateCmd) createKubernetes(workDir string, cubeToml model.CubeToml) error {
	conf.Version = Version
	conf.CommitId = CommitId
	conf.BuildDate = BuildDate

	// # 1
	utils.CheckDocker()

	cubeToml, _ = utils.ValidateCubeTomlConfig(workDir)

	//workDir, _ := os.Getwd()
	arg := os.Args

	commandName := "docker"
	commandArgs := []string{
		"docker",
		"run",
		"--name",
		"test",
		"--rm",
		"--privileged",
		"-it",
		"-v",
		fmt.Sprintf("%s:/cube/work", workDir),
		"-v",
		"basic.yaml:",
		"regi.acloud.run/library/knit:1.0.0",
		"ansible-playbook",
		"-i",
		"inventory.ini",
		"-u",
		"root",
		"--private-key",
		"id_rsa",
		"/cube/scripts/status.yml",
		"--step",
	}

	for i := 0; i < len(arg)-2; i++ {
		commandArgs = append(commandArgs, arg[i+2])
	}

	fmt.Printf("%s %s \n", commandName, commandArgs)

	err := syscall.Exec("/usr/local/bin/docker", commandArgs, os.Environ())

	log.Printf("Running command and waiting for it to finish...")
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	}

	//var (
	//	commandName string
	//	commandArgs []string
	//)
	//
	//idRsaPath := "/cube/cubescripts/id_rsa"
	//vaultPath := conf.CubeKey
	//
	//execMode := os.Getenv("MODE")
	//if execMode == "DEBUG" {
	//	idRsaPath = workDir + "/id_rsa"
	//	vaultPath = workDir + "/cube.key"
	//}
	//
	//parentDir := utils.ParentPath()
	////logger.Debugf("Working directory: %s", workDir)
	//
	//if cubeToml.Cube.ClosedNetwork {
	//
	//	if cubeToml.PrivateRegistry.PublicCert == false {
	//		cmd := exec.Command("sh",
	//			"-c",
	//			fmt.Sprintf("mkdir -p /etc/docker/certs.d/%s;wget --no-check-certificate -O /etc/docker/certs.d/%s/ca.crt https://%s/ca.crt", cubeToml.PrivateRegistry.RegistryIP, cubeToml.PrivateRegistry.RegistryIP, cubeToml.PrivateRegistry.RegistryIP),
	//		)
	//		cmdOutput := &bytes.Buffer{}
	//		cmd.Stdout = cmdOutput
	//		err := cmd.Start()
	//
	//		if err != nil {
	//			fmt.Printf(err.Error())
	//			os.Exit(1)
	//		}
	//		cmd.Wait()
	//	}
	//
	//}
	//
	//sshUserId := cubeToml.NodePool.Security.SSHUserID
	//utils.CopyFile0600(workDir+"/"+conf.CubeConfigFile, "/cube/cubescripts/roles/post-install/files/"+conf.CubeConfigFile) //cube.toml copy
	//
	//envIdRsa := os.Getenv("CUBE_ID_RSA")
	//if len(envIdRsa) > 0 {
	//	os.MkdirAll("/cube/cubescripts", os.ModePerm)
	//	c, _ := base64.StdEncoding.DecodeString(envIdRsa)
	//	//fmt.Println("CUBE_ID_RSA=" + string(c) + "\n")
	//	ioutil.WriteFile("/cube/cubescripts/id_rsa", []byte(string(c)+"\n"), 0600)
	//
	//	os.MkdirAll("/cube/work/generated", os.ModePerm)
	//	ioutil.WriteFile("/cube/work/generated/id_rsa", []byte(string(c)+"\n"), 0600)
	//
	//} else {
	//	utils.CopyFile0600(workDir+"/"+conf.CubeDestDir+"/id_rsa", "/cube/cubescripts/id_rsa") //private-key-path copy
	//}
	//
	//if c.target == "liteedge-master" || c.target == "liteedge-worker" {
	//	utils.CreateInventoryFile("", workDir, parentDir+"/cubescripts/inventories") //create inventory
	//} else {
	//	utils.CreateInventoryFile(c.target, workDir, parentDir+"/cubescripts/inventories") //create inventory
	//}
	//
	//utils.CreateAllYaml(workDir, parentDir+"/cubescripts") //crate all yaml
	//
	//commandArgs = []string{
	//	fmt.Sprintf("--vault-password-file=%s", vaultPath),
	//	"-i",
	//	parentDir + "/cubescripts/inventories/inventory",
	//	"-u",
	//	fmt.Sprintf("%s", sshUserId),
	//	"--private-key",
	//	idRsaPath,
	//	parentDir + conf.CreateYaml,
	//}
	//
	//// workDir + "/" + conf.CubeDestDir + "/id_rsa",
	//
	//os.Chdir(parentDir + "/cubescripts")
	//os.Setenv("ANSIBLE_CONFIG", parentDir+"/ansible.cfg")
	//
	//commandName = "ansible-playbook"
	//
	//switch c.target {
	//case "storage":
	//	commandArgs = append(commandArgs, "--tags")
	//	commandArgs = append(commandArgs, "storage")
	//
	//case "registry":
	//	commandArgs = append(commandArgs, "--tags")
	//	commandArgs = append(commandArgs, "registry")
	//case "addon":
	//	commandArgs = append(commandArgs, "--tags")
	//	commandArgs = append(commandArgs, "addon")
	//case "liteedge-master":
	//	if c.fast {
	//		commandArgs = append(commandArgs, "--start-at-task")
	//		commandArgs = append(commandArgs, "kubectl label node-role.liteedge/master=true")
	//	}
	//	commandArgs = append(commandArgs, "--tags")
	//	commandArgs = append(commandArgs, "liteedge-master")
	//case "liteedge-worker":
	//	if c.fast {
	//		commandArgs = append(commandArgs, "--start-at-task")
	//		commandArgs = append(commandArgs, "kubectl label node node-role.liteedge/edge=true")
	//	}
	//	commandArgs = append(commandArgs, "--tags")
	//	commandArgs = append(commandArgs, "liteedge-worker")
	//default:
	//
	//}
	//
	//if c.verbose {
	//	commandArgs = append(commandArgs, "-v")
	//}
	//
	//if c.dryRun {
	//	commandArgs = append(commandArgs, "-C")
	//	commandArgs = append(commandArgs, "-D")
	//}
	//
	//if cubeToml.Cube.DebugMode {
	//	fmt.Printf(strings.Replace(strings.Replace(fmt.Sprintf("playbook :\n %s %s", commandName, commandArgs), "[", "", -1), "]", "", -1) + "\n")
	//}
	//
	////if c.target == "liteedge-master" || c.target == "liteedge-worker" {
	////	infra.PrintAllYaml(workDir, "")
	////} else {
	////	infra.PrintAllYaml(workDir, c.target)
	////}
	//
	//if err := utils.ExecCmd(commandName, commandArgs); err != nil {
	//	return err
	//}
	//
	//if cubeToml.Cube.DebugMode == true && cubeToml.Cube.ClusterType == "kaas" {
	//	utils.CopyDir("/etc/kubernetes", workDir+"/"+conf.CubeDestDir)
	//}

	return nil
}
