package zkp

import (
	"encoding/binary"
	"errors"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
)

type CreateProofRequest struct {
	Signature fhks_bbs_plus.ThresholdSignature
	PublicKey fhks_bbs_plus.PublicKey
	Messages  [][]byte
	Revealed  []int
	Nonce     []byte
}

type SignatureProof struct {
	RevealedMessages map[int]SignatureMessage
	Proof            PoKOfSignatureProof
}

type PoKOfSignatureProof struct {
	APrime   *bls12381.PointG1
	ABar     *bls12381.PointG1
	D        *bls12381.PointG1
	ProofVC1 *ProofG1
	ProofVC2 *ProofG1
}

type ProofSpecificBlinding struct {
	Signature *SignatureMessage
}

type PoKOfSignature struct {
	APrime   bls12381.PointG1
	ABar     bls12381.PointG1
	D        bls12381.PointG1
	ProofVC1 ProverCommittedG1
	ProofVC2 ProverCommittedG1
	Secrets1 []*bls12381.Fr
	Secrets2 []*bls12381.Fr
	Revealed map[int]*SignatureMessage
}

func CreateProofBBS(messages [][]byte, sigBytes, nonce, pubKeyBytes []byte,
	revealedIndices []int) ([]byte, error) {

	frMsgs := ByteMsgToFr(messages)

	sig, err := fhks_bbs_plus.ThresholdSignatureFromBytes(sigBytes)
	if err != nil {
		return nil, errors.New("could not deserialize signature")
	}

	pubkey, err := fhks_bbs_plus.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return nil, errors.New("could not deserialize publickey")

	}

	proofmsgs, _, _, err := ProcessMessages(messages, revealedIndices, len(pubkey.H))
	if err != nil {
		panic(err)
	}

	if !pubkey.Verify(frMsgs, sig) {
		return nil, errors.New("the messages and signature do not match req.PublicKey.Verify")
	}
	sigmsgs := ExtractSignatureMessages(proofmsgs)

	pok, err := NewPoKOfSignature(sig, pubkey, revealedIndices, sigmsgs)

	if err != nil {
		return nil, fmt.Errorf("failed to initialize PoKOfSignature: %v", err)
	}

	// Step 4: Generate challenge bytes
	challengeBytes, err := pok.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PoKOfSignature: %v", err)
	}

	nonceFr := *bls12381.NewFr().FromBytes(nonce)
	nonceBytes := nonceFr.ToBytes()

	challengeBytes = append(challengeBytes, nonceBytes...)

	challFr := bls12381.NewFr().FromBytes(challengeBytes)

	challenge := &ProofChallenge{Fr: challFr}

	// Step 5: Generate final proof
	proof, err := pok.GenProof(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	payload := NewPoKPayload(pubkey.MessageCount(), revealedIndices)

	payloadBytes, err := payload.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to convert proof wrapper to bytes: %v", err)
	}

	proofBytes, err := proof.ToBytesCompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %v", err)
	}

	signatureProofBytes := append(payloadBytes, proofBytes...)
	return signatureProofBytes, nil
}

func (pok *PoKOfSignature) GenProof(challengeHash *ProofChallenge) (*PoKOfSignatureProof, error) {
	// Convert secrets_1 and secrets_2 to SignatureMessage format for consistency
	secrets1 := make([]SignatureMessage, len(pok.Secrets1))
	for i, s := range pok.Secrets1 {
		secrets1[i] = SignatureMessage{value: s}
	}

	secrets2 := make([]SignatureMessage, len(pok.Secrets2))
	for i, s := range pok.Secrets2 {
		secrets2[i] = SignatureMessage{value: s}
	}

	// Generate Proof VC1
	proofVC1, err := pok.ProofVC1.GenProof(challengeHash, secrets1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proofVC1: %v", err)
	}

	// Generate Proof VC2
	proofVC2, err := pok.ProofVC2.GenProof(challengeHash, secrets2)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proofVC2: %v", err)
	}

	return &PoKOfSignatureProof{
		APrime:   &pok.APrime,
		ABar:     &pok.ABar,
		D:        &pok.D,
		ProofVC1: proofVC1,
		ProofVC2: proofVC2,
	}, nil
}

func NewPoKOfSignature(signature *fhks_bbs_plus.ThresholdSignature, vk *fhks_bbs_plus.PublicKey, revealedIndices []int, sigMessages []*SignatureMessage) (*PoKOfSignature, error) {
	if len(sigMessages) != vk.MessageCount() {
		return nil, errors.New("public key generator message count mismatch")
	}

	frArray := convertToFrArray(sigMessages)

	if !signature.Verify(frArray, vk) {
		return nil, errors.New("the messages and signature do not match")
	}

	// this generates a random Fr value
	r1 := fhks_bbs_plus.GenerateRandomFr()
	r2 := fhks_bbs_plus.GenerateRandomFr()

	b := ComputeB(signature.S, sigMessages, vk)

	g1 := bls12381.NewG1()

	aPrime := g1.New().Set(signature.CapitalA)
	g1.MulScalar(aPrime, aPrime, r1)

	aBarDenom := g1.New().Set(aPrime)
	g1.MulScalar(aBarDenom, aBarDenom, signature.E)

	aBar := g1.New().Set(b)
	g1.MulScalar(aBar, aBar, r1)
	g1.Sub(aBar, aBar, aBarDenom)

	r2D := new(bls12381.Fr).Set(r2)
	r2D.Neg(r2D)

	commitmentBasesCount := 2

	builder := NewCommitmentBuilder(commitmentBasesCount)
	builder.Add(b, r1)
	builder.Add(vk.H0, r2D)

	d := builder.Build()

	r3 := new(bls12381.Fr).Set(r1)
	r3.Inverse(r3)

	sPrime := new(bls12381.Fr).Set(r2)
	sPrime.Mul(sPrime, r3)
	sPrime.Neg(sPrime)
	sPrime.Add(sPrime, signature.S)

	pokVC1, secrets1 := newVC1Signature(aPrime, vk.H0, signature.E, r2)

	negE := new(bls12381.Fr).Set(signature.E)
	negE.Neg(negE)

	proofVC2 := NewProverCommittingG1()

	negR3 := new(bls12381.Fr).Set(r3)
	negR3.Neg(negR3)

	proofVC2.Commit((*bls12381.PointG1)(d))
	proofVC2.Commit(vk.H0)

	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndices))

	for _, ind := range revealedIndices {
		revealedMessages[ind] = sigMessages[ind]
	}

	pokVC2, secrets2 := newVC2Signature(d, r3, vk, sPrime, sigMessages, revealedMessages)

	return &PoKOfSignature{
		APrime:   *aPrime,
		ABar:     *aBar,
		D:        bls12381.PointG1(*d),
		ProofVC1: *pokVC1,
		ProofVC2: *pokVC2,
		Secrets1: secrets1,
		Secrets2: secrets2,
		Revealed: revealedMessages,
	}, nil

}

func (proof *ProofG1) ToBytesCompressedForm() ([]byte, error) {
	var bytes []byte

	commitmentBytes := bls12381.NewG1().ToCompressed(&proof.Commitment)
	bytes = append(bytes, commitmentBytes...)

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proof.Responses)))
	bytes = append(bytes, lenBytes...)

	for _, response := range proof.Responses {
		responseBytes := response.ToBytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes, nil
}

func (proof *ProofG1) ToBytes() ([]byte, error) {
	var bytes []byte

	commitmentBytes := bls12381.NewG1().ToCompressed(&proof.Commitment)
	bytes = append(bytes, commitmentBytes...)

	for _, response := range proof.Responses {
		responseBytes := response.ToBytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes, nil
}

func (pcg *ProverCommittedG1) ToBytes() ([]byte, error) {
	var bytes []byte

	// Serialize each base (assuming each base is a PointG1)
	for _, base := range pcg.Bases {
		baseBytes := bls12381.NewG1().ToCompressed(base)
		bytes = append(bytes, baseBytes...)
	}

	// Serialize the commitment (assuming commitment is a PointG1)
	commitmentBytes := bls12381.NewG1().ToCompressed(pcg.Commitment)
	bytes = append(bytes, commitmentBytes...)

	return bytes, nil
}

func (pcg *ProverCommittedG1) GenProof(challenge *ProofChallenge, secrets []SignatureMessage) (*ProofG1, error) {
	// Ensure that the number of secrets matches the number of bases
	if len(secrets) != len(pcg.Bases) {
		return nil, fmt.Errorf("unequal number of bases (%d) and secrets (%d)", len(pcg.Bases), len(secrets))
	}

	// Initialize responses array
	responses := make([]*bls12381.Fr, len(pcg.Bases))

	for i := range pcg.Bases {
		// Compute c * secret_i (c is challenge * secret_i)
		c := new(bls12381.Fr).Set(challenge.Fr)
		c.Mul(c, secrets[i].value)

		// Compute blinding_factor_i - c * secret_i
		s := new(bls12381.Fr).Set(pcg.BlindingFactors[i])
		s.Sub(s, c)

		responses[i] = s // Store response
	}

	// Return the proof containing the commitment and responses
	return &ProofG1{
		Commitment: *pcg.Commitment,
		Responses:  responses,
	}, nil
}

func (pok *PoKOfSignature) ToBytes() ([]byte, error) {
	var bytes []byte
	aBarBytes := bls12381.NewG1().ToCompressed(&pok.ABar)
	bytes = append(bytes, aBarBytes...)

	proofVC1Bytes, err := pok.ProofVC1.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC1: %v", err)
	}
	bytes = append(bytes, proofVC1Bytes...)

	proofVC2Bytes, err := pok.ProofVC2.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC2: %v", err)
	}
	bytes = append(bytes, proofVC2Bytes...)

	return bytes, nil
}

func (proof *PoKOfSignatureProof) ToBytesCompressedForm() ([]byte, error) {
	var bytes []byte

	aPrimeBytes := bls12381.NewG1().ToCompressed(proof.APrime)
	bytes = append(bytes, aPrimeBytes...)

	aBarBytes := bls12381.NewG1().ToCompressed(proof.ABar)
	bytes = append(bytes, aBarBytes...)

	dBytes := bls12381.NewG1().ToCompressed(proof.D)
	bytes = append(bytes, dBytes...)

	proofVC1Bytes, err := proof.ProofVC1.ToBytesCompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC1: %v", err)
	}

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proofVC1Bytes)))
	bytes = append(bytes, lenBytes...)

	bytes = append(bytes, proofVC1Bytes...)

	proofVC2Bytes, err := proof.ProofVC2.ToBytesCompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC2: %v", err)
	}
	bytes = append(bytes, proofVC2Bytes...)

	return bytes, nil
}
