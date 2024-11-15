package zkp

import (
	"fmt"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
)

type Verifier struct{}

// NewProofRequest creates a new proof request
func (v *Verifier) NewProofRequest(revealedMessageIndices []int, verkey fhks_bbs_plus.PublicKey) (*ProofRequest, error) {
	revealedMessages := make(map[int]SignatureMessage)

	for _, i := range revealedMessageIndices {
		if i >= len(verkey.H) {
			return nil, fmt.Errorf("public key generator message count mismatch: %d > %d", i, len(verkey.H))
		}
		revealedMessages[i] = SignatureMessage{} // Initialize with default values or actual messages
	}

	return &ProofRequest{
		RevealedMessages: revealedMessages,
		VerificationKey:  verkey,
	}, nil
}

// VerifySignaturePoK verifies the signature proof of knowledge
func VerifySignaturePoK(proofRequest *ProofRequest, signatureProof *SignatureProof, nonce *ProofNonce) ([]SignatureMessage, error) {

	revealedMsgIndices := make(map[int]struct{})
	for index := range signatureProof.RevealedMessages {
		revealedMsgIndices[index] = struct{}{}
	}

	// Step 2: Serialize proof components into bytes using GetBytesForChallenge
	proofBytes, err := signatureProof.Proof.GetBytesForChallenge(revealedMsgIndices, &proofRequest.VerificationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %v", err)
	}

	// Append nonce bytes to create challenge input
	challengeBytes := append(proofBytes, nonce.Fr.ToBytes()...)

	// Hash the challenge input to create a challenge verifier
	challengeVerifier := helper.HashToFr(challengeBytes)
	// Verify the proof using the challenge verifier
	proofChall := &ProofChallenge{Fr: challengeVerifier}
	status, err := signatureProof.Proof.Verify(&proofRequest.VerificationKey, signatureProof.RevealedMessages, proofChall)
	if err != nil {
		return nil, fmt.Errorf("failed to verify proof: %v", err)
	}
	if status != Success {
		return nil, fmt.Errorf("invalid proof")
	}

	var revealedMessages []SignatureMessage
	for _, msg := range signatureProof.RevealedMessages {
		revealedMessages = append(revealedMessages, msg)
	}

	return revealedMessages, nil
}

func (v *Verifier) CreateChallengeHash(proofs []SignatureProof, proofRequests []ProofRequest, nonce *ProofNonce, claims [][]byte) (*ProofChallenge, error) {
	var bytes []byte

	for i := range proofs {
		// Convert map[int]SignatureMessage to map[int]struct{}
		revealedMsgIndices := make(map[int]struct{})
		for idx := range proofRequests[i].RevealedMessages {
			revealedMsgIndices[idx] = struct{}{}
		}

		// Pass the converted revealedMsgIndices to GetBytesForChallenge
		proofBytes, err := proofs[i].Proof.GetBytesForChallenge(revealedMsgIndices, &proofRequests[i].VerificationKey)
		if err != nil {
			panic(err)
		}
		bytes = append(bytes, proofBytes...)
	}

	bytes = append(bytes, nonce.Fr.ToBytes()...)

	for _, claim := range claims {
		bytes = append(bytes, claim...)
	}

	challenge := helper.HashToFr(bytes)
	return &ProofChallenge{Fr: challenge}, nil
}
