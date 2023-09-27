package issuecredential_test

import (
	"testing"
	"time"

	"github.com/perun-network/bbs-plus-threshold-wallet/wallet"
	aries_wallet "github.com/perun-network/bbs-plus-threshold-wallet/wallet/aries"
	"github.com/stretchr/testify/require"
)

const (
	// Issuer Institut
	endpointFaber = "localhost:26601"
	endpointAlice = "localhost:26602"
	endpointBob   = "localhost:26603"
	endpointCarl  = "localhost:26604"

	threshold = 2

	// Holder
	endpointHolder = "localhost:26610"

	// Time to wait for protocol to finish.
	sleepTime = 1 * time.Second
)

func TestThresholdIssueCredential(t *testing.T) {
	t.Run("Holder request Issuer for a signature to a credential", func(t *testing.T) {
		runThresholdIssueCredential(t)
	})
}

func runThresholdIssueCredential(t *testing.T) {
	require := require.New(t)

	// Setup Issuer Parties.
	t.Log("Set up Issuer Organisation.")
	aliceWallet, err := aries_wallet.NewAriesWallet("Alice", endpointAlice, []byte("Hello World"))
	require.NoError(err, "create and setup Alice's wallet")
	alice := wallet.NewPartyWallet(aliceWallet)

	bobWallet, err := aries_wallet.NewAriesWallet("Bob", endpointBob, []byte("Bob"))
	require.NoError(err, "create and setup Bob's wallet")
	bob := wallet.NewPartyWallet(bobWallet)

	carlWallet, err := aries_wallet.NewAriesWallet("Carl", endpointCarl, []byte("Carl"))
	require.NoError(err, "create and setup Carl's wallet")
	carl := wallet.NewPartyWallet(carlWallet)

	//Setup Threshold Issuer with threshold (2 out of 3).
	faberWallet, err := aries_wallet.NewAriesWallet("Faber Institut", endpointFaber, []byte("Faber Institut"))
	require.NoError(err, "create and setup Faber's wallet")
	faber := wallet.NewThresholdWallet(faberWallet)
	faber.AddParticipant(alice)
	faber.AddParticipant(bob)
	faber.AddParticipant(carl)
	faber.UpdateThreshold(threshold)

	// Setup Holder.
	t.Log("Set up Holder.")
	holderWallet, err := aries_wallet.NewAriesWallet("Holder", endpointHolder, []byte("holder's password"))
	require.NoError(err, "create and setup Holder's wallet")
	holder := wallet.NewThresholdWallet(holderWallet)

	// Issuer generates precomputations and collectionID.
	publicKey, collectionID, err := faber.GeneratePrecomputation(1)
	require.NoError(err, "create precomputations and collectionID")
	holder.Store(publicKey)

	// Credential.
	t.Log("Holder Request Credential Signature.")
	credential := wallet.NewDocument(
		wallet.Credential,
		[]byte("holder's english certificate A1"),
		collectionID,
		faber.ID)
	holder.Store(credential)

	// Issuer signs credential.
	t.Log("Issuer signs Credential.")
	faber.Store(credential)
	indices := []int{1, 2}
	signature, err := faber.SignThresholdSignature(
		[]*wallet.Document{credential},
		indices)
	require.NoError(err, "create threshold signature")

	// Holder verifies the signature.
	t.Log("Holder verifies Signature.")
	holder.Store(signature)
	isTrue, err := holder.VerifyThresholdSignature([]*wallet.Document{credential}, signature, publicKey)
	require.NoError(err, "verify signature error")
	require.True(isTrue, "verify signature failed")
	t.Log("Verification successful")

	// Close wallets.
	t.Log("Close Wallets")
	err = faber.Close()
	require.NoError(err, "close faber institut account")
	err = holder.Close()
	require.NoError(err, "close holder account")
}
