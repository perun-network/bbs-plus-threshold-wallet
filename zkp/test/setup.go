package test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"

	"github.com/stretchr/testify/assert"
	"testing"
)

type KeyPairTest struct {
	SecretKey fhks_bbs_plus.SecretKey
	PublicKey fhks_bbs_plus.PublicKey
}

func CreateTestKeyPair(t *testing.T, msgCount int) KeyPairTest {
	sk := fhks_bbs_plus.SecretKey{Fr: fhks_bbs_plus.GenerateRandomFr()}
	pk := *sk.GetPublicKey(msgCount)
	return KeyPairTest{SecretKey: sk, PublicKey: pk}
}

func CreateProofReqNoNonce(t *testing.T, kp KeyPairTest, msgs [][]byte, revealed []int) zkp.CreateProofRequest {
	CheckRevealedIndices(t, msgs, revealed)

	e := fhks_bbs_plus.GenerateRandomFr()
	s := fhks_bbs_plus.GenerateRandomFr()

	pk := kp.PublicKey

	frMsgs := zkp.ByteMsgToFr(msgs)

	sig := kp.SecretKey.Sign(pk, frMsgs, e, s)

	ok := pk.Verify(frMsgs, sig)
	assert.True(t, ok, "signature verification failed")

	proofNoChall := zkp.CreateProofRequest{
		Signature: *sig,
		PublicKey: pk,
		Messages:  msgs,
		Revealed:  revealed,
	}

	return proofNoChall
}

func CheckRevealedIndices(t *testing.T, msgs [][]byte, revealed []int) {
	maxIndex := -1
	for _, index := range revealed {
		if index > maxIndex {
			maxIndex = index
		}
	}

	assert.LessOrEqual(t, maxIndex, len(msgs)-1, "the highest revealed index exceeds the number of messages")
}
