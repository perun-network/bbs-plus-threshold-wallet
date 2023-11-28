package demo

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
	"perun.network/go-perun/log"
)

// Config contains all configuration read from config.yaml and network.yaml
type Config struct {
	Alias  string
	Node   nodeConfig
	Wallet walletConfig
	// Read from the network.yaml. The key is the alias.
	Peers map[string]*netConfigEntry
}

type netConfigEntry struct {
	Endpoint string
}

type nodeConfig struct {
	Endpoint       string // Inbound endpoint for Aries Framework
	WalletExpiry   time.Duration
	SigningTimeout time.Duration
	DialTimeout    time.Duration
}

type walletConfig struct {
	ID            string
	Password      string
	Threshold     int
	Servers       int
	Presigs       int
	ContractSetup string              // contract setup method
	contractSetup contractSetupOption //
}

type contractSetupOption int

var contractSetupOptions [3]string = [...]string{"signer", "holder", "generator"}

const (
	contractSetupOptionSigner contractSetupOption = iota
	contractSetupOptionHolder
	contractSetupOptionGenerator
)

func (option contractSetupOption) String() string {
	return contractSetupOptions[option]
}

func parseContractSetupOption(s string) (option contractSetupOption, err error) {
	for i, optionString := range contractSetupOptions {
		if s == optionString {
			option = contractSetupOption(i)
			return
		}
	}

	err = fmt.Errorf("invalid value for config option 'contractsetup': the value is '%s', but must be one of '%v'", s, contractSetupOptions)
	return
}

var config Config

// GetConfig returns a pointer to the current `Config`.
// This is needed to make viper and cobra work together.
func GetConfig() *Config {
	return &config
}

// SetConfig called by viper when the config file was parsed
func SetConfig() {
	// Load config files
	viper.SetConfigFile(flags.cfgFile)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	viper.SetConfigFile(flags.cfgNetFile)
	if err := viper.MergeInConfig(); err != nil {
		log.Fatalf("Error reading network config file, %s", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Fatal(err)
	}

	var err error
	if config.Wallet.contractSetup, err = parseContractSetupOption(config.Wallet.ContractSetup); err != nil {
		log.Fatal(err)
	}
}
