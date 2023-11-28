package demo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/perun-network/bbs-plus-threshold-wallet/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"perun.network/go-perun/log"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet/thresholdwallet"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

type peer struct {
	alias string
	log   log.Logger
}

type node struct {
	log log.Logger

	client    thresholdwallet.Wallet
	generator thresholdwallet.PrecomputationsGenerator
	aries     *aries.Aries

	// Protects peers
	mtx   sync.Mutex
	peers map[string]*peer
}

func (n *node) Connect(args []string) error {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	return n.connect(args[0])
}

func (n *node) connect(alias string) error {
	n.log.Traceln("Connecting...")
	if n.peers[alias] != nil {
		return errors.New("Peer already connected.")
	}

	peerCfg, ok := config.Peers[alias]
	if !ok {
		return errors.Errorf("Alias '%s' unknown. Add it to 'network.yaml'.", alias)
	}

	n.peers[alias] = &peer{
		alias: alias,
		log:   log.WithField("peer", peerCfg),
	}

	return nil
}

func (n *node) Invite(args []string) error {
	if config.Wallet.contractSetup == contractSetupOptionSigner {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		peerName := args[0]
		peer := n.peers[peerName]
		if peer != nil {
			if err := n.connect(peerName); err != nil {
				return err
			}
		}
		invitation, err := n.client.Invite(peerName)
		if err != nil {
			return err
		}
		jsonInvitation, err := json.MarshalIndent(invitation, "", "")
		if err != nil {
			return errors.WithMessage(err, "create json inviation")
		}

		fmt.Println()
		logrus.Printf("Invitation: \n" + util.Format(util.GREEN, string(jsonInvitation)))
		fmt.Println()

		logrus.Println("Connection request processing...")
		fmt.Println()

		ctx, cancel := context.WithTimeout(context.Background(), config.Node.DialTimeout)
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("time out while waiting for connection")
			default:
				if _, err := n.client.GetConnection(invitation.ID); err == nil {
					time.Sleep(time.Second)

					fmt.Println()
					logrus.Printf("Aries connection was established.")
					fmt.Println()
					return nil
				}
			}
		}
	}
	return errors.New("node is not supported.")
}

// InputInvitation opens a prompt for the user to enter an Aries DID Invitation from another peer for connection.
func (n *node) InputInvitation(args []string) error {
	if config.Wallet.contractSetup == contractSetupOptionHolder {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		peerName := args[0]
		peer := n.peers[peerName]
		if peer == nil {
			if err := n.connect(peerName); err != nil {
				return err
			}
		}
		Prompt("Invite details: ", func(userInput string) {
			ctx, cancel := context.WithTimeout(context.Background(), config.Node.DialTimeout)
			defer cancel()

			done := make(chan error, 1)

			go func() {
				invitation := &didexchange.Invitation{}
				err := json.Unmarshal([]byte(userInput), invitation)
				if err != nil {
					done <- errors.WithMessage(err, "unmarshalling invitation")
					return
				}
				_, err = n.client.Connect(invitation)
				if err != nil {
					done <- errors.WithMessage(err, "accepting did exchange connection")
					return
				}
				time.Sleep(time.Second)
				conn, err := n.client.GetConnection(invitation.ID)
				if err != nil {
					done <- errors.WithMessage(err, "get connection")
					return
				}
				// Add Clients to respective collectionID's signing party.
				if holder, ok := n.client.(*thresholdwallet.Holder); ok {
					if err = holder.AddPartySigner(args[1], conn); err != nil {
						done <- errors.WithMessage(err, "add party signer")
						return
					}
					done <- nil
					return
				}
				done <- errors.New("client is not from type Holder")
			}()
			select {
			case <-ctx.Done():
				logrus.Errorf(errors.WithMessage(ctx.Err(), "input invitation timeout").Error())
				return
			case err := <-done:
				if err != nil {
					logrus.Errorf(err.Error())
					return
				}
				time.Sleep(time.Second)
				fmt.Println()
				logrus.Printf("Aries connection was established.")
				fmt.Println()
				return
			}
		})
		return nil
	}
	return errors.New("node is not supported")
}

// ImportPublicKey opens a prompt for the user to enter the encrypted public key string given the collection ID.
func (n *node) ImportPublicKey(args []string) error {
	if config.Wallet.contractSetup != contractSetupOptionGenerator {
		n.mtx.Lock()
		defer n.mtx.Unlock()

		Prompt("Input encrypted public key string: ", func(userInput string) {
			ctx, cancel := context.WithTimeout(context.Background(), config.Node.DialTimeout)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				publicKeyByte, err := base64.StdEncoding.DecodeString(userInput)
				if err != nil {
					done <- errors.WithMessage(err, "decrypt public key")
					return
				}

				publicKeyDoc := thresholdwallet.NewDocument(thresholdwallet.PublicKey, publicKeyByte, args[0])

				err = n.client.Store(publicKeyDoc)
				if err != nil {
					done <- errors.WithMessage(err, "store public key")
					return
				}
				fmt.Println()
				logrus.Println("✅ Public key imported: " + util.Format(util.GREEN, publicKeyDoc.ID))
				fmt.Println()
				done <- nil
			}()

			select {
			case <-ctx.Done():
				logrus.Errorf(errors.WithMessage(ctx.Err(), "input timeout").Error())
				return
			case err := <-done:
				if err != nil {
					logrus.Errorf(err.Error())
					return
				}
				return
			}
		})
		return nil
	}
	return errors.New("node is not supported")
}

// ImportPrecomputation opens a prompt for the user to enter the encrypted precomputation string given the collection ID.
func (n *node) ImportPrecomputation(args []string) error {
	if config.Wallet.contractSetup == contractSetupOptionSigner {
		n.mtx.Lock()
		defer n.mtx.Unlock()

		Prompt("Input encrypted precomputation string: ", func(userInput string) {
			ctx, cancel := context.WithTimeout(context.Background(), config.Node.DialTimeout)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				precomputationByte, err := base64.StdEncoding.DecodeString(userInput)
				if err != nil {
					done <- errors.WithMessage(err, "decrypt public key")
					return
				}

				publicKeyDoc := thresholdwallet.NewDocument(thresholdwallet.Precomputation, precomputationByte, args[0])

				err = n.client.Store(publicKeyDoc)
				if err != nil {
					done <- errors.WithMessage(err, "store public key")
					return
				}
				done <- nil
			}()

			select {
			case <-ctx.Done():
				logrus.Errorf(errors.WithMessage(ctx.Err(), "input timeout").Error())
				return
			case err := <-done:
				if err != nil {
					logrus.Errorf(err.Error())
					return
				}
				time.Sleep(time.Second)
				fmt.Println()
				logrus.Println("✅ Precomputation imported.")
				fmt.Println()
				return
			}
		})
		return nil
	}
	return errors.New("node is not supported")
}

// NextIndex called by the generator, returns an index for next signing.
func (n *node) NextIndex() error {
	if config.Wallet.contractSetup == contractSetupOptionGenerator {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		nextIndex, err := n.generator.NextMsgIndex()
		if err != nil {
			return errors.WithMessage(err, "get next signing index")
		}
		fmt.Println()
		logrus.Println("Next Index for Signing: " + util.Format(util.GREEN, fmt.Sprint(nextIndex)))
		fmt.Println()
		return nil
	}
	return errors.New("node is not supported")
}

// SetIndex will be used by holder to set the threshold for signing messages from the same collectionID.
func (n *node) SetThreshold(args []string) error {
	if config.Wallet.contractSetup == contractSetupOptionHolder {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		threshold, err := strconv.Atoi(args[1])
		if err != nil {
			return err
		}

		err = n.client.(*thresholdwallet.Holder).SetThreshold(args[0], threshold)
		if err != nil {
			return errors.WithMessage(err, "set threshold")
		}
		fmt.Println()
		logrus.Println("✅ Threshold for signing set.")
		fmt.Println()
		return nil
	}
	return errors.New("node is not supported")
}

// SignThresholCredential called by holder to send a credential to participating signers;
// after received all partial signatures, combine and create signed verifiable credential.
func (n *node) SignThresholdCredential(args []string) error {
	if config.Wallet.contractSetup == contractSetupOptionHolder {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		relativePath := convertToRelativePath(args[0])
		// Open JSON the JSON file.
		vcByte, err := os.ReadFile(relativePath)
		if err != nil {
			return errors.WithMessage(err, "open json file")
		}

		logrus.Println("Holder want a signature for the credential:")
		fmt.Println(util.Format(util.YELLOW, string(vcByte)))

		// Set message index.
		index, err := strconv.Atoi(args[2])
		if err != nil {
			return err
		}

		if err = n.client.(*thresholdwallet.Holder).SetNextMsgIndex(args[1], index); err != nil {
			return errors.WithMessage(err, "set message index")
		}

		vc, err := verifiable.ParseCredential(vcByte,
			verifiable.WithCredDisableValidation(),
			verifiable.WithDisabledProofCheck())
		if err != nil {
			return errors.WithMessage(err, "parse raw credential")
		}

		vcByte, err = vc.MarshalJSON()
		if err != nil {
			return errors.WithMessage(err, "marshal raw credential")
		}
		credDoc := &thresholdwallet.Document{
			ID:           vc.ID,
			Type:         thresholdwallet.Credential,
			Content:      vcByte,
			CollectionID: args[1],
		}

		// Holder send proposal to participating signers.
		logrus.Println("Holder sends proposal to participating signers...")
		signedCredDoc, err := n.client.Sign(credDoc)
		if err != nil {
			return errors.WithMessage(err, "signing threshold credential")
		}

		logrus.Println("Holder gets the signed credential:")
		fmt.Println(util.Format(util.YELLOW, string(signedCredDoc.Content)))
		n.client.Store(signedCredDoc)
		fmt.Println()
		fmt.Println("Signed Credential " + util.Format(util.PURPLE, signedCredDoc.ID) + " stored in the wallet.")
		fmt.Println()
		return nil
	}
	return errors.New("node is not supported, expected holder")
}

// Verify is used to verify the holder's signed credential with its stored public key.
func (n *node) Verify(args []string) error {
	if config.Wallet.contractSetup == contractSetupOptionHolder {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		fmt.Println()
		logrus.Println("Retrieve signed document")
		fmt.Println()
		signedCredDoc, err := n.client.Get(thresholdwallet.Credential, args[1], args[0])
		if err != nil {
			return errors.WithMessage(err, "get credential")
		}

		logrus.Println("Retrieve public key")
		fmt.Println()
		publicKeyDoc, err := n.client.Get(thresholdwallet.PublicKey, args[2], args[0])
		if err != nil {
			return errors.WithMessage(err, "get public key")
		}

		verificationResult, err := n.client.Verify(signedCredDoc, publicKeyDoc)
		if err != nil {
			return errors.WithMessage(err, "credential verification failed")
		}
		if verificationResult {
			logrus.Println("✅ " + util.Format(util.BLUE, "Credential verified."))
		}
		fmt.Println()
		return nil
	}
	return errors.New("node is not supported, expected holder")
}

// ExistsPeer checks if the peer exists.
func (n *node) ExistsPeer(alias string) bool {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	return n.peers[alias] != nil
}

// Exit exits the demo and release resources.
func (n *node) Exit([]string) error {
	if config.Wallet.contractSetup != contractSetupOptionGenerator {
		n.mtx.Lock()
		defer n.mtx.Unlock()
		n.log.Traceln("Exiting...")
		return n.aries.Close()
	}
	return nil
}
