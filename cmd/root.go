package cmd

import (
	"encoding/base64"
	"github.com/hhkbp2/go-logging"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"kore-on/pkg/conf"
	"kore-on/pkg/utils"
)

var logger = logging.GetLogger("command")
var rootFlags = struct {
	provider    string
	configFile  string
	cubeToolUrl string
	mode        string
	debug       bool
	help        bool
}{}

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "koreonctl",
	Short: "Install kubernetes cluster to on-premise system with registry and storage system",
	Long:  `edge-cube, It install kubernetes cluster and add-on service.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// To cleanup previous running or exited cube container
	cobra.OnInitialize(initConfig)

	RootCmd.AddCommand(
		versionCmd,
		initCmd(),
		createCmd(),
		destroyCmd(),
		applyCmd(),
		prepareAiregapCmd(),
	)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	workDir, _ := os.Getwd()
	conf.BaseDir = workDir

	if rootFlags.cubeToolUrl != "" {
		conf.ImageName = rootFlags.cubeToolUrl
	}

	if rootFlags.mode == "c" {
		conf.IsCliMode = false
	}

	if rootFlags.configFile != "" {
		// Use config file from the flag. It may be local file path or http url
		if strings.HasPrefix(rootFlags.configFile, "http") {
			logger.Debugf("downloading config file from %s\n", rootFlags.configFile)
			if err := DownloadFile("./cube.yaml", rootFlags.configFile, true); err != nil {
				logger.Errorf("fail to get cube.yaml file: %s", err.Error())
				os.Exit(1)
			}

			rootFlags.configFile = workDir + "/cube.yaml"
		} else if rootFlags.debug {
			utils.WriteFileString(workDir+"/cube.yaml", "test")
			rootFlags.configFile = workDir + "/cube.yaml"
		}
		viper.SetConfigFile(rootFlags.configFile)
	}

	// If a config file is found, read it in.
	if utils.FileExists(rootFlags.configFile) {
		if err := viper.ReadInConfig(); err != nil {
			logger.Errorf("%s", err.Error())
			os.Exit(1)
		}
	}

	if !conf.IsCliMode {
		//logger.Infof("decode private key  [%s]", viper.GetString("private_key_path"))
		data, err := base64.StdEncoding.DecodeString(viper.GetString("private_key_path"))
		if err != nil {
			logger.Errorf("ssh private key decode failed [%s]", err.Error())
			os.Exit(1)
		}

		ioutil.WriteFile(workDir+"/id_rsa", data, 0600)

		//logger.Infof("decode public key  [%s]", viper.GetString("key_path"))
		data, err = base64.StdEncoding.DecodeString(viper.GetString("key_path"))
		if err != nil {
			logger.Errorf("ssh public key decode failed [%s]", err.Error())
			os.Exit(1)
		}

		ioutil.WriteFile(workDir+"/id_rsa.pub", data, 0600)
	}

}

func DownloadFile(filepath string, url string, d bool) error {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if d {
		bytes, _ := ioutil.ReadAll(resp.Body)
		data, _ := base64.StdEncoding.DecodeString(string(bytes))

		if err := utils.WriteFileString(filepath, string(data)); err != nil {
			return err
		}
	} else {
		// Write the body to file
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return err
		}
	}
	return nil
}
