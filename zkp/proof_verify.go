package zkp

import (
	"errors"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
)

type ProofG1 struct {
	Commitment bls12381.PointG1
	Responses  []*bls12381.Fr
}

func (proof *ProofG1) GetChallengeContribution(bases []*bls12381.PointG1, commitment *bls12381.PointG1, challenge *ProofChallenge) *bls12381.PointG1 {
	points := append(bases, commitment)
	scalars := append(proof.Responses, challenge.Fr)
	return MultiScalarMulVarTimeG1(points, scalars)
}

func (proof *ProofG1) Verify(bases []*bls12381.PointG1, commitment *bls12381.PointG1, challenge *ProofChallenge) error {
	// Step 1: Compute the challenge contribution using multi-scalar multiplication

	contribution := proof.GetChallengeContribution(bases, commitment, challenge)

	// Step 2: Subtract the stored commitment from the challenge contribution
	g1 := bls12381.NewG1()
	g1.Sub(contribution, contribution, &proof.Commitment)

	// Step 3: Check if result is zero (identity element)
	if g1.IsZero(contribution) {
		return nil
	}

	return errors.New("proof verification failed")
}

type ExternalBlinding struct {
	Signature *SignatureMessage
	Nonce     ProofNonce
}

type ProofChallenge struct {
	*bls12381.Fr
}

type HiddenMessage struct {
	ProofSpecific *ProofSpecificBlinding
	External      *ExternalBlinding
}

type ProofNonce struct {
	Fr *bls12381.Fr
}

func (p *ProofNonce) ToBytes() []byte {
	return p.Fr.ToBytes()
}

type ProofMessage struct {
	Revealed *SignatureMessage
	Hidden   *HiddenMessage
}

type SignatureMessage struct {
	value *bls12381.Fr
}

func VerifyBBSProof(messagesBytes [][]byte, proof, nonce, pubKeyBytes []byte) error {

	payload, err := ParsePoKPayload(proof)
	if err != nil {
		return fmt.Errorf("parse ParsePoKPayload failed : %w", err)
	}

	signatureProof, err := ParseSignatureProof(proof[payload.LenInBytes():])
	if err != nil {
		return fmt.Errorf("ParseSignatureProof: %w", err)
	}

	pk, err := fhks_bbs_plus.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	msgSigmsg := FrToSigMessages(messagesBytes)

	revealedMessages := make(map[int]*SignatureMessage)
	for i := range payload.revealed {
		revealedMessages[payload.revealed[i]] = msgSigmsg[i]
	}
	if len(payload.revealed) > len(msgSigmsg) {
		return fmt.Errorf("payload revealed longer than signature messages")
	}

	challengeBytes := signatureProof.GetBytesForChallenge(revealedMessages, pk)

	proofNonce := ParseProofNonce(nonce)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	proofChallenge := bls12381.NewFr().FromBytes(challengeBytes)

	return signatureProof.Verify(proofChallenge, pk, revealedMessages, msgSigmsg)
}

func (proof *PoKOfSignatureProof) verifyVC1Proof(challenge *bls12381.Fr, pk *fhks_bbs_plus.PublicKey) error {
	basesVC1 := []*bls12381.PointG1{proof.APrime, pk.H0}
	aBarD := &bls12381.PointG1{}
	bls12381.NewG1().Sub(aBarD, proof.ABar, proof.D)
	chall := &ProofChallenge{Fr: challenge}
	err := proof.ProofVC1.Verify(basesVC1, aBarD, chall)
	if err != nil {
		return fmt.Errorf("verification of ProofVC1 failed: %v", err)
	}
	return nil
}

func (proof *PoKOfSignatureProof) verifyVC2Proof(challenge *bls12381.Fr, pubKey *fhks_bbs_plus.PublicKey, revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage) error {
	// Step 1: Calculate the number of revealed messages
	revealedMessagesCount := len(revealedMessages)

	// Step 2: Initialize bases for VC2 and disclosed messages
	basesVC2 := make([]*bls12381.PointG1, 0, 2+pubKey.MessageCount()-revealedMessagesCount)
	basesVC2 = append(basesVC2, proof.D, pubKey.H0)

	basesDisclosed := []*bls12381.PointG1{bls12381.NewG1().One()} // Start with G1 generator
	exponents := []*bls12381.Fr{bls12381.NewFr().One()}           // Start with scalar 1

	// Step 3: Separate revealed and hidden messages
	revealedMessagesInd := 0
	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pubKey.H[i])
			exponents = append(exponents, messages[revealedMessagesInd].value)
			revealedMessagesInd++
		} else {
			basesVC2 = append(basesVC2, pubKey.H[i])
		}
	}

	// Step 4: Compute pr = g1 * h1^-m1 * h2^-m2.... for all disclosed messages
	posPr := MultiScalarMulVarTimeG1(basesDisclosed, exponents)

	// Negate pr to compute pr^-1
	g1 := bls12381.NewG1()
	negPr := g1.New()
	g1.Neg(negPr, posPr)

	// Step 5: Verify VC2 proof
	chall := &ProofChallenge{Fr: challenge}
	err := proof.ProofVC2.Verify(basesVC2, negPr, chall)
	if err != nil {
		return fmt.Errorf("verification of ProofVC2 failed: %v", err)
	}

	return nil
}

func (proof *PoKOfSignatureProof) Verify(proofChallenge *bls12381.Fr, vk *fhks_bbs_plus.PublicKey, revealedMsgs map[int]*SignatureMessage, messages []*SignatureMessage) error {
	if err := vk.Validate(); err != nil {
		return err
	}

	for i := range revealedMsgs {
		if i >= len(vk.H) {
			return fmt.Errorf("index %d should be less than %d", i, len(vk.H))
		}
	}

	if IsPointZero(proof.APrime) {
		return errors.New("bad signature")
	}

	g1 := bls12381.NewG1()

	aBarNeg := &bls12381.PointG1{}
	g1.Neg(aBarNeg, proof.ABar)

	pairingCheck := bls12381.NewEngine()
	pairingCheck.AddPair(proof.APrime, vk.W)
	pairingCheck.AddPair(aBarNeg, bls12381.NewG2().One())

	if !pairingCheck.Check() {
		return errors.New("bad signature")
	}

	err := proof.verifyVC1Proof(proofChallenge, vk)
	if err != nil {
		return fmt.Errorf("verification of ProofVC1 failed: %v", err)
	}

	err = proof.verifyVC2Proof(proofChallenge, vk, revealedMsgs, messages)
	if err != nil {
		return fmt.Errorf("verification of ProofVC2 failed: %v", err)
	}

	return nil
}

func (sp *PoKOfSignatureProof) GetBytesForChallenge(revealedMessages map[int]*SignatureMessage,
	pubKey *fhks_bbs_plus.PublicKey) []byte {
	hiddenCount := pubKey.MessageCount() - len(revealedMessages)

	bytesLen := (7 + hiddenCount) * helper.LenBytesG1Compressed
	bytes := make([]byte, 0, bytesLen)

	g1 := bls12381.NewG1()
	aBarBytes := g1.ToCompressed(sp.ABar)

	bytes = append(bytes, aBarBytes...)
	aPrimeBytes := g1.ToCompressed(sp.APrime)
	bytes = append(bytes, aPrimeBytes...)
	h0Bytes := g1.ToCompressed(pubKey.H0)
	bytes = append(bytes, h0Bytes...)
	commVC1Bytes := g1.ToCompressed(&sp.ProofVC1.Commitment)
	bytes = append(bytes, commVC1Bytes...)
	dBytes := g1.ToCompressed(sp.D)

	bytes = append(bytes, dBytes...)
	bytes = append(bytes, h0Bytes...)

	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; !ok {
			hBytes := g1.ToCompressed(pubKey.H[i])
			bytes = append(bytes, hBytes...)
		}
	}
	commVC2Bytes := g1.ToCompressed(&sp.ProofVC2.Commitment)
	bytes = append(bytes, commVC2Bytes...)

	return bytes
}

func ParseSignatureProof(sigProofBytes []byte) (*PoKOfSignatureProof, error) {
	if len(sigProofBytes) < helper.LenBytesG1Compressed*3 {
		return nil, errors.New("invalid size of signature proof")
	}

	g1Points := make([]*bls12381.PointG1, 3)
	offset := 0

	g1 := bls12381.NewG1()

	for i := range g1Points {
		g1Point, err := g1.FromCompressed(sigProofBytes[offset : offset+helper.LenBytesG1Compressed])
		if err != nil {
			return nil, fmt.Errorf("parse G1 point: %w", err)
		}

		g1Points[i] = g1Point
		offset += helper.LenBytesG1Compressed
	}

	proof1BytesLen := int(uint32FromBytes(sigProofBytes[offset : offset+4]))
	offset += 4

	proofVc1, err := ParseProofG1(sigProofBytes[offset : offset+proof1BytesLen])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	offset += proof1BytesLen

	proofVc2, err := ParseProofG1(sigProofBytes[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &PoKOfSignatureProof{

		APrime:   g1Points[0],
		ABar:     g1Points[1],
		D:        g1Points[2],
		ProofVC1: proofVc1,
		ProofVC2: proofVc2,
	}, nil
}

func ParseProofNonce(proofNonceBytes []byte) *ProofNonce {
	return &ProofNonce{
		bls12381.NewFr().FromBytes(proofNonceBytes),
	}
}

func ParseProofG1(bytes []byte) (*ProofG1, error) {
	if len(bytes) < helper.LenBytesG1Compressed+4 {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	offset := 0

	commitment, err := bls12381.NewG1().FromCompressed(bytes[:helper.LenBytesG1Compressed])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point: %w", err)
	}

	offset += helper.LenBytesG1Compressed
	length := int(uint32FromBytes(bytes[offset : offset+4]))
	offset += 4

	if len(bytes) < helper.LenBytesG1Compressed+4+length*helper.LenBytesFr {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*bls12381.Fr, length)
	for i := 0; i < length; i++ {
		responses[i] = bls12381.NewFr().FromBytes(bytes[offset : offset+helper.LenBytesFr])
		offset += helper.LenBytesFr
	}

	return NewProofG1(*commitment, responses), nil
}

func NewProofG1(commitment bls12381.PointG1, responses []*bls12381.Fr) *ProofG1 {
	return &ProofG1{
		Commitment: commitment,
		Responses:  responses,
	}
}
