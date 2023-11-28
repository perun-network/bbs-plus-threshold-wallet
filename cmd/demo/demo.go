package demo

import (
	"bufio"
	"fmt"
	"os"

	"github.com/c-bata/go-prompt"
	"github.com/spf13/cobra"
)

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Multiple parties Threshold Credential Swap Demo",
	Long: `Enables a holder to issue a credential through partial signing from 3-out-of-5 signers.
	It illustrates that Aries Verifiable Credential Client can be integrated with BBS+ Threshold Signature Scheme.`,
	Run: runDemo,
}

// CommandLineFlags contains the command line flags.
type CommandLineFlags struct {
	cfgFile    string
	cfgNetFile string
	useStdIO   bool
}

var flags CommandLineFlags

func init() {
	demoCmd.PersistentFlags().StringVar(&flags.cfgFile, "config", "", "General config file")
	demoCmd.PersistentFlags().StringVar(&flags.cfgNetFile, "network", "network.yaml", "Network config file")
	demoCmd.PersistentFlags().BoolVar(&flags.useStdIO, "stdio", false, "Read from stdin")
}

// GetDemoCmd exposes demoCmd so that it can be used as a sub-command by another cobra command instance.
func GetDemoCmd() *cobra.Command {
	return demoCmd
}

// runDemo is executed everytime the program is started with the `demo` sub-command.
func runDemo(c *cobra.Command, args []string) {
	Setup()
	if flags.useStdIO {
		runWithStdIO(executor)
	} else {
		p := prompt.New(
			executor,
			completer,
			prompt.OptionPrefix("> "),
			prompt.OptionTitle("perun"),
		)
		p.Run()
	}
}

func runWithStdIO(executor func(string)) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("> ")
	for scanner.Scan() {
		executor(scanner.Text())
		fmt.Printf("> ")
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error scanning stdin: %v\n", err)
		os.Exit(1)
	}
}

func completer(prompt.Document) []prompt.Suggest {
	return []prompt.Suggest{}
}

// executor wraps the demo executor to print error messages.
func executor(in string) {
	AddInput(in)
}
