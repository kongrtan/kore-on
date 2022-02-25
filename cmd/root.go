package cmd

import (
	"github.com/hhkbp2/go-logging"
	"github.com/spf13/cobra"
	"os"
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
	RootCmd.AddCommand(
		versionCmd,
		initCmd(),
		createCmd(),
		destroyCmd(),
		applyCmd(),
		prepareAirgapCmd(),
	)
}
