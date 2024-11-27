package zkp_test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/test"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	zkptest "github.com/perun-network/bbs-plus-threshold-wallet/zkp/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignVerify(t *testing.T) {
	kp := zkptest.CreateTestingKP(t, len(test.Messages))
	e := fhks_bbs_plus.GenerateRandomFr()
	s := fhks_bbs_plus.GenerateRandomFr()

	frMsgs := zkp.ByteMsgToFr(test.Messages)
	sig := kp.SecretKey.Sign(kp.PublicKey, frMsgs, e, s)
	ok := kp.PublicKey.Verify(frMsgs, sig)
	assert.True(t, ok, "signature verification failed")
}

func TestNewCreateProof(t *testing.T) {
	msgNum := 5
	msgs := test.Messages[:msgNum]

	kp := zkptest.CreateTestingKP(t, msgNum)

	revealed := test.Revealed
	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)

	sigBytes, err := proofRqNoNonce.Signature.ToBytes()
	pubkeyBytes := proofRqNoNonce.PublicKey.Serialize()
	assert.NoError(t, err, "signature serialization failed")
	nonce := []byte("nonce")
	_, err = zkp.CreateProofBBS(msgs, sigBytes, nonce, pubkeyBytes, revealed)
	assert.NoError(t, err, "CreateProofBBS should not return an error")

}

func TestVerifyBBSProof(t *testing.T) {
	msgNum := 5
	msgs := test.Messages[:msgNum]

	kp := zkptest.CreateTestingKP(t, msgNum)

	revealed := test.Revealed
	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)
	sigBytes, err := proofRqNoNonce.Signature.ToBytes()
	pubkeyBytes := proofRqNoNonce.PublicKey.Serialize()

	assert.NoError(t, err, "signature serialization failed")
	nonce := []byte("nonce")
	proofBytes, err := zkp.CreateProofBBS(msgs, sigBytes, nonce, pubkeyBytes, revealed)
	assert.NoError(t, err, "creation of BBS proof failed")
	assert.NotEmpty(t, proofBytes, "empty BBS proof")
	revealedMessages := make([][]byte, len(revealed))
	for i, ind := range revealed {
		revealedMessages[i] = msgs[ind]
	}
	pubkeybytes := kp.PublicKey.Serialize()
	assert.NoError(t, zkp.VerifyBBSProof(revealedMessages, proofBytes, nonce, pubkeybytes), "verification of BBS proof failed")

}
