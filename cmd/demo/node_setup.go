package demo

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet/thresholdwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/perun-network/bbs-plus-threshold-wallet/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"perun.network/go-perun/log"
)

const (
	externalPrefix = "http://"
)

var (
	backend *node
)

func Setup() {
	SetConfig()
	var err error
	if backend, err = newNode(); err != nil {
		log.WithError(err).Fatalln("could not initialize node.")
	}
}

func newNode() (*node, error) {
	n := &node{
		log:   log.Get(),
		peers: make(map[string]*peer),
	}
	return n, n.setup()
}

// setup does:
//   - Create a new offChain account.
//   - Create a client with the node's dialer, funder, adjudicator and wallet.
//   - Set up a TCP listener for incoming connections.
//   - Load or create the database and setting up persistence with it.
//   - Set the OnNewChannel, Proposal and Update handler.
//   - Print the configuration.
func (n *node) setup() error {
	contractSetup := config.Wallet.contractSetup
	switch contractSetup {
	case contractSetupOptionHolder:
		var err error
		logrus.Println("Start setting up...")
		inbound, err := http.NewInbound(config.Node.Endpoint, externalPrefix+config.Node.Endpoint, "", "")
		if err != nil {
			return errors.WithMessage(err, "create inbound transport")
		}

		documentLoader, err := testutil.DocumentLoader()
		if err != nil {
			return errors.WithMessage(err, "create document loader")
		}
		n.aries, err = aries.New(aries.WithInboundTransport(inbound), aries.WithJSONLDDocumentLoader(documentLoader))
		if err != nil {
			return errors.WithMessage(err, "initialize aries client")
		}

		ctx, err := n.aries.Context()
		if err != nil {
			return errors.WithMessage(err, "get context")
		}

		err = thresholdwallet.CreateProfile(config.Alias, ctx, wallet.WithPassphrase(config.Wallet.Password))
		if err != nil {
			return errors.WithMessage(err, "create wallet profile")
		}

		n.client, err = thresholdwallet.NewHolder(config.Alias,
			config.Node.SigningTimeout,
			ctx,
			wallet.WithUnlockByPassphrase(config.Wallet.Password),
			wallet.WithUnlockExpiry(config.Node.WalletExpiry))
		if err != nil {
			return errors.WithMessage(err, "create new holder")
		}

		// Watch for wallet expiration.
		go watchWalletExpiry(config.Node.WalletExpiry)

		logrus.Println("Setup DIDComm Handler.")
		// Holder can use default handler because its automatically accepts the partial signatures.
		// if err = n.client.DefaultHandler(); err != nil {
		// 	return errors.WithMessage(err, "start DIDComm Handler")
		// }

		actionsIssueCredential := make(chan service.DIDCommAction)
		err = n.client.CustomHandler(actionsIssueCredential, func(events chan service.DIDCommAction) {
			db, storeErr := ctx.ProtocolStateStorageProvider().OpenStore(thresholdwallet.StoreName)

			for event := range events {
				if storeErr != nil {
					event.Stop(fmt.Errorf("failed to open transient store: %w", storeErr))
					continue
				}
				var (
					arg     interface{}
					options *rfc0593.CredentialSpecOptions
					err     error
				)
				messType := event.Message.Type()
				switch messType {
				case issuecredential.OfferCredentialMsgTypeV2:
					fmt.Println()
					logrus.Println("🔁 Incoming credential offer. ")
					arg, options, err = n.client.ReplayOffer(event.Message)
					err = thresholdwallet.SaveOptionsIfNoError(err, db, event.Message, options)
					logrus.Println("Send back request to corresponding signer.")
				case issuecredential.IssueCredentialMsgTypeV2:
					fmt.Println()
					logrus.Println("🔁 Incoming partial signed credential. Accept and combine with other partial signatures.")
					arg, _, err = n.client.ReplayCredential(db, event.Message)
				default:
					event.Stop(fmt.Errorf("unsupported issue credential messages"))
					continue
				}

				if err != nil {
					event.Stop(err)
					continue
				}
				event.Continue(arg)
			}
		})
		if err != nil {
			return errors.WithMessage(err, "start DIDComm handler")
		}
		n.PrintConfig()
		fmt.Println()
		logrus.Println("✅ Holder ready.")
		return nil
	case contractSetupOptionSigner:
		var err error

		inbound, err := http.NewInbound(config.Node.Endpoint, externalPrefix+config.Node.Endpoint, "", "")
		if err != nil {
			return errors.WithMessage(err, "create inbound transport")
		}

		documentLoader, err := testutil.DocumentLoader()
		if err != nil {
			return errors.WithMessage(err, "create document loader")
		}
		n.aries, err = aries.New(aries.WithInboundTransport(inbound), aries.WithJSONLDDocumentLoader(documentLoader))
		if err != nil {
			return errors.WithMessage(err, "initialize aries client")
		}

		ctx, err := n.aries.Context()
		if err != nil {
			return errors.WithMessage(err, "get context")
		}

		err = thresholdwallet.CreateProfile(config.Alias, ctx, wallet.WithPassphrase(config.Wallet.Password))
		if err != nil {
			return errors.WithMessage(err, "create wallet profile")
		}

		n.client, err = thresholdwallet.NewPartySigner(
			config.Alias,
			ctx,
			wallet.WithUnlockByPassphrase(config.Wallet.Password),
			wallet.WithUnlockExpiry(config.Node.WalletExpiry))
		if err != nil {
			return errors.WithMessage(err, "create new signer")
		}

		// Watch for Wallet expiration.
		go watchWalletExpiry(config.Node.WalletExpiry)

		// Setup DIDComm for DIDExchange and Issue Credential
		logrus.Println("Setup DIDComm handler.")
		// if err = n.client.DefaultHandler(); err != nil {
		// 	return errors.WithMessage(err, "start DIDComm Handler")
		// }
		actionsIssueCredential := make(chan service.DIDCommAction)
		err = n.client.CustomHandler(actionsIssueCredential, func(events chan service.DIDCommAction) {
			db, storeErr := ctx.ProtocolStateStorageProvider().OpenStore(thresholdwallet.StoreName)

			for event := range events {
				if storeErr != nil {
					event.Stop(fmt.Errorf("failed to open transient store: %w", storeErr))
					continue
				}

				var (
					arg     interface{}
					options *rfc0593.CredentialSpecOptions
					err     error
				)
				var promptFinished = make(chan bool)

				switch event.Message.Type() {
				case issuecredential.ProposeCredentialMsgTypeV2:
					fmt.Println()
					msg := fmt.Sprintf("🔁 Incoming credential proposal. " + util.Format(util.PURPLE, "Accept(y/n)? "))
					Prompt(msg, func(input string) {
						if input == "y" {
							arg, options, err = n.client.ReplayProposal(event.Message)
							err = thresholdwallet.SaveOptionsIfNoError(err, db, event.Message, options)
							logrus.Println("Sent back offer to holder.")
						} else {
							err = errors.New("Signer rejected the proposal")
						}
						promptFinished <- true
					})
				case issuecredential.RequestCredentialMsgTypeV2:
					fmt.Println()
					msg := fmt.Sprintf("🔁 Incoming credential request. " + util.Format(util.PURPLE, "Accept(y/n)?"))
					Prompt(msg, func(input string) {
						if input == "y" {
							arg, options, err = n.client.ReplayRequest(event.Message)
							err = thresholdwallet.SaveOptionsIfNoError(err, db, event.Message, options)
							logrus.Println("Sent back partial signed credential to holder.")
						} else {
							err = errors.New("Signer rejected the offer, partial signature was not created.")
						}
						promptFinished <- true
					})

				default:
					event.Stop(fmt.Errorf("unsupported issue credential message type"))
					continue
				}
				// Wait for prompt to finish if it was started.
				<-promptFinished
				if err != nil {
					event.Stop(err)
					continue
				}
				event.Continue(arg)
			}
		})

		if err != nil {
			return errors.WithMessage(err, "start DIDComm handler")
		}

		n.PrintConfig()
		fmt.Println()

		logrus.Println("✅ Signer ready.")
		return nil
	case contractSetupOptionGenerator:
		n.generator = thresholdwallet.NewThresholdBBSPlusGenerator()
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		if err != nil {
			return errors.WithMessage(err, "create random seed")
		}

		collectionID, publicKeyDoc, precomputationDocs, err := n.generator.GeneratePrecomputation(
			sha256.New,
			seed,
			config.Wallet.Threshold,
			config.Wallet.Servers,
			config.Wallet.Presigs)
		if err != nil {
			return errors.WithMessage(err, "create precomputations")
		}
		fmt.Println("Precomputation with CollectionIDs: " + util.Format(util.GREEN, collectionID))
		fmt.Println("Public Key: " + util.Format(util.PURPLE, base64.StdEncoding.EncodeToString(publicKeyDoc.Content)))
		for i, precompDoc := range precomputationDocs {
			fmt.Println(fmt.Sprintf("Precomputation for Signer %d: ", i) +
				util.Format(util.BLUE, base64.StdEncoding.EncodeToString(precompDoc.Content)))
		}
		logrus.Printf("✅ Precomputation generated for %s servers with threshold %s and %s presignatures.",
			util.Format(util.YELLOW, fmt.Sprint(config.Wallet.Servers)),
			util.Format(util.YELLOW, fmt.Sprint(config.Wallet.Threshold)),
			util.Format(util.YELLOW, fmt.Sprint(config.Wallet.Presigs)))
		fmt.Println()
		return nil
	default:
		// unsupported setup method
		return errors.New(fmt.Sprintf("Unsupported contract setup method '%s'.", contractSetup))
	}
}

// PrintConfig prints out the information of the node.
func (n *node) PrintConfig() error {
	fmt.Printf("\n"+
		"Alias: "+"%s\n"+
		"Listening: "+"%s\n",
		util.Format(util.GREEN, config.Alias), util.Format(util.GREEN, config.Node.Endpoint))

	fmt.Println("Known peers:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	for alias, peer := range config.Peers {
		fmt.Fprintf(w, "%s\t%s\n", alias, peer.Endpoint)
	}
	return w.Flush()
}

func watchWalletExpiry(expiry time.Duration) {
	timeout := time.After(expiry)

	// Wait for timeout and warns the user.
	<-timeout
	util.Format(util.RED, "Wallet expired!")
	panic("wallet is expired, need to restart the demo")
}
