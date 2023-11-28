package demo

import (
	"fmt"
	"os"

	"strings"

	"github.com/perun-network/bbs-plus-threshold-wallet/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"perun.network/go-perun/log"
)

type argument struct {
	Name      string
	Validator func(string) error
}

type command struct {
	Name     string
	Args     []argument
	Help     string
	Function func([]string) error
}

var commands []command
var generatorCmds []string
var holderCmds []string
var signerCmds []string

func init() {

	commands = []command{
		{
			"invite",
			[]argument{{"Peer", valAlias}},
			"Issuer produces an invitation link for the given peer. The parameter is the peer's alias. \nExample: invite alice",
			func(args []string) error { return backend.Invite(args) },
		}, {
			"connect",
			[]argument{{"Peer", valAlias}, {"collectionID", valCollection}},
			"Holder inputs an invitation from peer and will send back the public key to establish an Aries connection. \nExample: connect faber did:collection:example",
			func(args []string) error { return backend.InputInvitation(args) },
		}, {
			"import-pk",
			[]argument{{"collectionID", valCollection}},
			"The clients import the given public key into its wallet, given the collectionID.\n Example: import-pk did:collection:example",
			func(args []string) error { return backend.ImportPublicKey(args) },
		}, {
			"import-precomp",
			[]argument{{"collectionID", valCollection}},
			"Signer imports a given precomputation, given its collectionID.\n Example: import-precomp did:collection:example",
			func(args []string) error { return backend.ImportPrecomputation(args) },
		}, {
			"next-index",
			[]argument{},
			"Generator gives the next index of the presignature to be used for signing. \nExample: next-index",
			func(args []string) error { return backend.NextIndex() },
		}, {
			"set-threshold",
			[]argument{{"collectionID", valCollection}, {"threshold", valUInt}},
			"Holder set the threshold for signing messages from the collectionID. \nExample: set-threshold did:collection:example 3",
			func(args []string) error { return backend.SetThreshold(args) },
		}, {
			"sign",
			[]argument{{"file-path", valFile}, {"collectionID", valCollection}, {"index", valUInt}},
			"Holder sends a document that needed a credential to all issuers and used the partial signatures to compute the threshold signatures. \nExample: sign-credential vc.json did:collection:example 0",
			func(args []string) error { return backend.SignThresholdCredential(args) },
		}, {
			"verify",
			[]argument{{"collectionID", valCollection}, {"credentialID", valCredential}, {"pkID", valPublicKey}},
			"Holder verify the signed credential with BBS+ signature and public key.\n Example: verify did:collection:example did:credential:signedVC did:public_key:pk",
			func(args []string) error { return backend.Verify(args) },
		}, {
			"config",
			nil,
			"Print the current configuration and known peers.",
			func([]string) error { return backend.PrintConfig() },
		}, {
			"help",
			nil,
			"Prints all possible commands.",
			printHelp,
		}, {
			"exit",
			nil,
			"Exits the program.",
			func(args []string) error {
				if err := backend.Exit(args); err != nil {
					log.Error("err while exiting: ", err)
				}
				os.Exit(0)
				return nil
			},
		},
	}

	generatorCmds = []string{"next-index", "help, exit"}
	holderCmds = []string{"connect", "import-pk", "set-threshold", "sign", "verify", "config", "help", "exit"}
	signerCmds = []string{"import-precomp", "invite", "config", "help", "exit"}
}

var prompts = make(chan func(string), 1)

// AddInput adds an input to the input command queue.
func AddInput(in string) {
	select {
	case f := <-prompts:
		f(in)
	default:
		if err := Execute(in); err != nil {
			logrus.Errorf("\033[0;33m⚡\033[0m %s", err)
			fmt.Println()
		}
	}
}

// Prompt waits for input on the command line and then executes the given
// function with the input.
func Prompt(msg string, f func(string)) {
	logrus.Println(msg)
	prompts <- f
}

// Execute interprets commands entered by the user.
func Execute(in string) error {
	in = strings.TrimSpace(in)
	args := strings.Split(in, " ")
	command := args[0]
	args = args[1:]

	log.Tracef("Reading command '%s'\n", command)
	for _, cmd := range commands {
		if cmd.Name == command {
			if len(args) != len(cmd.Args) {
				return errors.Errorf("Invalid number of arguments, expected %d but got %d", len(cmd.Args), len(args))
			}
			for i, arg := range args {
				if err := cmd.Args[i].Validator(arg); err != nil {
					return errors.WithMessagef(err, "'%s' argument invalid for '%s': %v", cmd.Args[i].Name, command, arg)
				}
			}
			return cmd.Function(args)
		}
	}
	if len(command) > 0 {
		return errors.Errorf("Unknown command: %s. Enter \"help\" for a list of commands.", command)
	}
	return nil
}

func printHelp(args []string) error {
	for _, cmd := range commands {
		switch config.Wallet.contractSetup {
		case contractSetupOptionGenerator:
			if contains(generatorCmds, cmd.Name) {
				fmt.Print(util.Format(util.PURPLE, cmd.Name), " ")
				for _, arg := range cmd.Args {
					fmt.Printf("<%s> ", arg.Name)
				}
				fmt.Printf("\n\t%s\n\n", strings.ReplaceAll(util.Format(util.GREEN, cmd.Help), "\n", "\n\t"))
			}
		case contractSetupOptionHolder:
			if contains(holderCmds, cmd.Name) {
				fmt.Print(util.Format(util.PURPLE, cmd.Name), " ")
				for _, arg := range cmd.Args {
					fmt.Printf("<%s> ", arg.Name)
				}
				fmt.Printf("\n\t%s\n\n", strings.ReplaceAll(util.Format(util.GREEN, cmd.Help), "\n", "\n\t"))
			}
		case contractSetupOptionSigner:
			if contains(signerCmds, cmd.Name) {
				fmt.Print(util.Format(util.PURPLE, cmd.Name), " ")
				for _, arg := range cmd.Args {
					fmt.Printf("<%s> ", arg.Name)
				}
				fmt.Printf("\n\t%s\n\n", strings.ReplaceAll(util.Format(util.GREEN, cmd.Help), "\n", "\n\t"))
			}
		default:
			return errors.Errorf("Unknown contract setup option: %v", config.Wallet.contractSetup)
		}
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
