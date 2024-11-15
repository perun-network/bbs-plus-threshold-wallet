package test

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"

	"github.com/perun-network/bbs-plus-threshold-wallet/test"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"

	"github.com/stretchr/testify/assert"
	"testing"
)

var RevealedTest = []int{0, 2}

type KeyPairTest struct {
	SecretKey fhks_bbs_plus.SecretKey
	PublicKey fhks_bbs_plus.PublicKey
}

func CreateTestingKP(t *testing.T, msgCount int) KeyPairTest {
	sk := fhks_bbs_plus.SecretKey{Fr: fhks_bbs_plus.GenerateRandomFr()}
	pk := *sk.GetPublicKey(msgCount)
	return KeyPairTest{SecretKey: sk, PublicKey: pk}
}

func CreateProofReqNoNonce(t *testing.T, kp KeyPairTest, msgs [][]byte, revealed []int) zkp.CreateProofRequest {
	CheckRevealedIndices(t, msgs, revealed)

	e := fhks_bbs_plus.GenerateRandomFr()
	s := fhks_bbs_plus.GenerateRandomFr()

	pk := kp.PublicKey

	hashMsgs := make([]*bls12381.Fr, len(msgs))

	for i, msg := range msgs {
		hashMsgs[i] = helper.HashToFr(msg)
	}

	sig := kp.SecretKey.Sign(pk, hashMsgs, e, s)

	ok := pk.Verify(hashMsgs, sig)
	assert.True(t, ok, "signature verification failed")

	proofNoChall := zkp.CreateProofRequest{
		Signature: *sig,
		PublicKey: pk,
		Messages:  msgs,
		Revealed:  revealed,
	}

	return proofNoChall
}

func CreateProofRequest(t *testing.T, kp KeyPairTest) zkp.CreateProofRequest {
	msgs := test.Messages
	rev := test.Revealed
	CheckRevealedIndices(t, msgs, rev)

	e := fhks_bbs_plus.GenerateRandomFr()
	s := fhks_bbs_plus.GenerateRandomFr()

	pk := kp.PublicKey

	hashMsgs := make([]*bls12381.Fr, len(msgs))

	for i, msg := range msgs {
		hashMsgs[i] = helper.HashToFr(msg)
	}

	sig := kp.SecretKey.Sign(pk, hashMsgs, e, s)

	ok := pk.Verify(hashMsgs, sig)

	proofNoChall := zkp.CreateProofRequest{
		Signature: *sig,
		PublicKey: pk,
		Messages:  msgs,
		Revealed:  rev,
	}

	_, proofBBSBytes, err := zkp.CreateProofBBS(proofNoChall)
	assert.NoError(t, err, "error when creating BBS proof")

	assert.True(t, ok, "signature verification failed")
	return zkp.CreateProofRequest{
		Signature: *sig,
		PublicKey: pk,
		Messages:  msgs,
		Revealed:  rev,
		Nonce:     proofBBSBytes,
	}
}

func CheckRevealedIndices(t *testing.T, msgs [][]byte, revealed []int) {
	// Step 1: Find the maximum index in Revealed
	maxIndex := -1
	for _, index := range revealed {
		if index > maxIndex {
			maxIndex = index
		}
	}

	// Step 2: Assert that the highest entry in Revealed is at most len(msgs) - 1
	assert.LessOrEqual(t, maxIndex, len(msgs)-1, "the highest revealed index exceeds the number of messages")
}
