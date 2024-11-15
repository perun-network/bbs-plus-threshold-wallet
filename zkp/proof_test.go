package zkp_test

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
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

	hashMsgs := make([]*bls12381.Fr, len(test.Messages))
	for i, msg := range test.Messages {
		hashMsgs[i] = helper.HashToFr(msg)
	}
	sig := kp.SecretKey.Sign(kp.PublicKey, hashMsgs, e, s)
	ok := kp.PublicKey.Verify(hashMsgs, sig)
	assert.True(t, ok, "signature verification failed")
}

func TestNewCreateProof(t *testing.T) {
	msgNum := 5

	kp := zkptest.CreateTestingKP(t, msgNum)

	msgs := test.Messages[:msgNum]
	revealed := []int{}
	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)

	_, _, err := zkp.CreateProofBBS(proofRqNoNonce)
	assert.NoError(t, err, "CreateProofBBS should not return an error")

}

func TestGenPokOfSignature(t *testing.T) {

	msgNum := 5

	msgs := test.Messages[:msgNum]
	revealed := []int{}

	kp := zkptest.CreateTestingKP(t, msgNum)

	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)

	sigmsgs, revIdxSet, err := zkp.ProcessMessages(proofRqNoNonce.Messages, revealed, kp.PublicKey.MessageCount())
	checkFields(sigmsgs)

	assert.NoError(t, err, "ProcessMessages should not return an error")

	pokSig, err := zkp.NewPoKOfSignature(proofRqNoNonce.Signature, proofRqNoNonce.PublicKey, sigmsgs)
	assert.NoError(t, err, "NewPoKOfSignature should not return an error")
	challengeBytes, err := pokSig.ToBytes()
	assert.NoError(t, err, "ToBytes should not return an error")

	if len(proofRqNoNonce.Nonce) == 0 {
		challengeBytes = append(challengeBytes, make([]byte, helper.FR_UNCOMPRESSED_SIZE)...)
	} else {
		nonce := helper.HashToFr(proofRqNoNonce.Nonce).ToBytes()
		challengeBytes = append(challengeBytes, nonce...)
	}

	challenge := &zkp.ProofChallenge{Fr: helper.HashToFr(challengeBytes)}

	sigProof, err := pokSig.GenProof(challenge)
	// Initialize a map to store revealed messages
	revealedMsgs := make(map[int]zkp.SignatureMessage)

	// Iterate over revealed indices (zkptest.RevealedTest)

	for _, idx := range revealed {
		if sigmsgs[idx].Revealed != nil {
			// Insert the message at index 'idx' from sigmsgs into revealedMsgs
			revealedMsgs[idx] = *sigmsgs[idx].Revealed
		}
	}
	for idx, msg := range revealedMsgs {
		fmt.Printf("Index: %d, Revealed: %v", idx, msg)
	}

	assert.NoError(t, err, "GenProof should not return an error")

	chalBytes, err := sigProof.GetBytesForChallenge(revIdxSet, &proofRqNoNonce.PublicKey)
	assert.NoError(t, err, "GetBytesForChallenge should not return an error")

	chalVerifier := zkp.ProofChallenge{helper.HashToFr(chalBytes)}
	_, err = sigProof.Verify(&proofRqNoNonce.PublicKey, revealedMsgs, &chalVerifier)
	assert.NoError(t, err, "Verify should not return an error")

}

func TestVerifyPokOfSignature(t *testing.T) {
	kp := zkptest.CreateTestingKP(t, len(test.Messages))
	msgNum := 5

	msgs := test.Messages[:msgNum]
	revealed := []int{}
	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)

	msgsRaw := test.Messages
	revIdx := zkptest.RevealedTest

	sigmsgs, _, err := zkp.ProcessMessages(msgsRaw, revIdx, kp.PublicKey.MessageCount())
	assert.NoError(t, err, "ProcessMessages should not return an error")

	pokSig, err := zkp.NewPoKOfSignature(proofRqNoNonce.Signature, proofRqNoNonce.PublicKey, sigmsgs)

	challengeBytes, err := pokSig.ToBytes()
	assert.NoError(t, err, "ToBytes should not return an error")

	if len(proofRqNoNonce.Nonce) == 0 {
		challengeBytes = append(challengeBytes, make([]byte, helper.FR_UNCOMPRESSED_SIZE)...)
	} else {
		nonce := helper.HashToFr(proofRqNoNonce.Nonce).ToBytes()
		challengeBytes = append(challengeBytes, nonce...)
	}

	challenge := &zkp.ProofChallenge{Fr: helper.HashToFr(challengeBytes)}

	_, err = pokSig.GenProof(challenge)
	assert.NoError(t, err, "GenProof should not return an error")

}

func TestVerifyBBSProof(t *testing.T) {

	kp := zkptest.CreateTestingKP(t, len(test.Messages))
	msgNum := 5

	msgs := test.Messages[:msgNum]
	revealed := []int{}
	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)

	pokSigWrapper, pokSigBytes, err := zkp.CreateProofBBS(proofRqNoNonce)
	assert.NoError(t, err, "creation of BBS proof failed")

	verifyProofCtx := zkp.VerifyProofContext{
		Proof:     *pokSigWrapper,
		PublicKey: kp.PublicKey,
		Messages:  test.Messages,
		Nonce:     pokSigBytes,
	}

	resp, err := zkp.VerifyBBSProof(verifyProofCtx)
	assert.NoError(t, err, "verification of BBS proof failed")
	assert.True(t, resp.Verified, "verification should be successful")

}

func checkFields(sigmsgs []zkp.ProofMessage) {
	for i, msg := range sigmsgs {
		fmt.Printf("Message %d:\n", i)

		// Check Revealed field
		if msg.Revealed != nil {
			fmt.Printf("  Revealed: %v\n", msg.Revealed.Get())
		} else {
			fmt.Println("  Revealed: Not populated")
		}

		// Check Hidden field
		if msg.Hidden != nil {
			fmt.Println("  Hidden:")

			if msg.Hidden.ProofSpecific != nil {
				fmt.Printf("    ProofSpecific Signature: %v\n", msg.Hidden.ProofSpecific.Signature.Get())
			} else {
				fmt.Println("    ProofSpecific: Not populated")
			}

			if msg.Hidden.External != nil {
				fmt.Printf("    External Signature: %v\n", msg.Hidden.External.Signature.Get())
				fmt.Printf("    External Nonce: %v\n", msg.Hidden.External.Nonce.Fr)
			} else {
				fmt.Println("    External: Not populated")
			}
		} else {
			fmt.Println("  Hidden: Not populated")
		}
	}
}
