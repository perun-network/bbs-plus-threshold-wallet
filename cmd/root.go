package cmd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/perun-network/bbs-plus-threshold-wallet/cmd/demo"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:              "aries-threshold-demo",
	Short:            "Aries Threshold Wallet Credential Swap Demo",
	Long:             `Demonstrator for the Integration of BBS+ Threshold Wallet in Aries Agent.`,
	PersistentPreRun: runRoot,
}

func runRoot(c *cobra.Command, args []string) {
	setConfig()
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	defer func() {
		if err := recover(); err != nil {
			logrus.Panicf("err=%s, trace=%s\n", err, debug.Stack())
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logConfig.Level, "log-level", "warn", "Logrus level")
	err := viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	if err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().StringVar(&logConfig.File, "log-file", "", "log file")
	err = viper.BindPFlag("log.file", rootCmd.PersistentFlags().Lookup("log-file"))
	if err != nil {
		panic(err)
	}

	rootCmd.AddCommand(demo.GetDemoCmd())
}
