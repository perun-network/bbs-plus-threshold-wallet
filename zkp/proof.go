package zkp

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"math/rand"
)

type BlindSignature struct {
	A *bls12381.PointG1
	e *bls12381.Fr
	s *bls12381.Fr
}

type VerifyProofContext struct {
	Proof     PoKOfSignatureProofWrapper
	PublicKey fhks_bbs_plus.PublicKey
	Messages  [][]byte
	Nonce     []byte
}

type SignatureProof struct {
	RevealedMessages map[int]SignatureMessage // Map of revealed messages
	Proof            PoKOfSignatureProof      // The actual proof structure
}

type PoKOfSignatureProofWrapper struct {
	BitVector []byte
	Proof     *PoKOfSignatureProof
}

type PoKOfSignatureProof struct {
	APrime   bls12381.PointG1
	ABar     bls12381.PointG1
	D        bls12381.PointG1
	ProofVC1 ProofG1
	ProofVC2 ProofG1
}
type PoKOfSignatureProofStatus int

const (
	Success PoKOfSignatureProofStatus = iota
	BadSignature
	BadHiddenMessage
	BadRevealedMessage
)

type SignatureBlinding struct {
	*bls12381.Fr
}

type ProofSpecificBlinding struct {
	Signature SignatureMessage
}

type ProofG1Old struct {
	Commitment bls12381.PointG1 // The proof commitment of all base_0*exp_0+base_1*exp_1...
	Responses  []*bls12381.Fr   // s values in the Fiat-Shamir protocol
}

type ProofG1 struct {
	Commitment bls12381.PointG1 // The proof commitment of all base_0*exp_0+base_1*exp_1...
	Responses  []*bls12381.Fr   // s values in the Fiat-Shamir protocol
}

func (proof *ProofG1) Verify(bases []bls12381.PointG1, commitment *bls12381.PointG1, challenge *ProofChallenge) (bool, error) {
	// Step 1: Compute the challenge contribution using multi-scalar multiplication

	basesWithCommitment := append(bases, *commitment)
	scalarsWithChallenge := append(proof.Responses, challenge.Fr)

	// Step 2: Compute the challenge contribution using multi-scalar multiplication
	challengeContribution := MultiScalarMulConstTimeG1(basesWithCommitment, scalarsWithChallenge)

	// challengeContribution := MultiScalarMulConstTimeG1(bases, proof.Responses)

	// Step 2: Subtract the stored commitment from the challenge contribution
	g1 := bls12381.NewG1()
	result := g1.New() //.Zero()
	g1.Sub(result, &challengeContribution, &proof.Commitment)

	// Step 3: Check if result is zero (identity element)
	if g1.IsZero(result) {
		return true, nil
	}

	return false, fmt.Errorf("proof verification failed")
}

// ExternalBlinding represents an external blinding for hidden messages
type ExternalBlinding struct {
	Signature SignatureMessage
	Nonce     ProofNonce
}

type ProofChallenge struct {
	*bls12381.Fr
}

// HiddenMessage represents a hidden message in proofs, which can be either proof-specific or external blinding
type HiddenMessage struct {
	ProofSpecific *ProofSpecificBlinding
	External      *ExternalBlinding
}

// ProofNonce represents a nonce in proofs
type ProofNonce struct {
	Fr *bls12381.Fr
}

func (v *Verifier) GenerateProofNonce() *ProofNonce {
	nonce := bls12381.NewFr()

	_, err := nonce.Rand(crand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate secure nonce: %v", err))
	}

	return &ProofNonce{Fr: nonce}
}

// ProofMessage represents a proof message which can be revealed or hidden
type ProofMessage struct {
	Revealed *SignatureMessage
	Hidden   *HiddenMessage
}

type BbsVerifyResponse struct {
	Verified bool
	Error    string
}

func NewProofRequest(messages []ProofMessage, publicKey fhks_bbs_plus.PublicKey, revealedIndices []int) ProofRequest {
	revealedMessages := make(map[int]SignatureMessage)

	for _, idx := range revealedIndices {
		if idx < len(messages) && messages[idx].Revealed != nil {
			revealedMessages[idx] = *messages[idx].Revealed
		}
	}

	return ProofRequest{
		RevealedMessages: revealedMessages,
		VerificationKey:  publicKey,
	}
}

type SignatureMessage struct {
	value *bls12381.Fr
}

type ProofRequest struct {
	RevealedMessages map[int]SignatureMessage // Map to store revealed messages by index
	VerificationKey  fhks_bbs_plus.PublicKey  // Existing PublicKey type
}

func (msg *SignatureMessage) Get() *bls12381.Fr {
	return msg.value
}

func (msg *SignatureMessage) Set(value *bls12381.Fr) {
	msg.value = value
}

func VerifyBBSProof(request VerifyProofContext) (BbsVerifyResponse, error) {
	var response BbsVerifyResponse

	// Check if proof and public key are valid
	if request.Proof.Proof == nil || request.PublicKey.H0 == nil {
		response.Verified = false
		response.Error = "invalid proof or public key"
		return response, errors.New(response.Error)
	}

	var nonce *bls12381.Fr
	if len(request.Nonce) == 0 {
		nonce = bls12381.NewFr().Zero() // Default nonce if empty
	} else {
		nonce = helper.HashToFr(request.Nonce) // Hash the nonce if provided
	}

	messages := request.Messages

	revealedIndices, proof := request.Proof.Unwrap()

	revealedMessages := make(map[int]SignatureMessage)
	for idx := range revealedIndices {
		if idx < len(messages) {
			revealedMessages[idx] = SignatureMessage{value: helper.HashToFr(messages[idx])}
		}
	}

	proofRequest := ProofRequest{
		RevealedMessages: revealedMessages,
		VerificationKey:  request.PublicKey,
	}

	signatureProof := SignatureProof{
		RevealedMessages: revealedMessages,
		Proof:            *proof,
	}

	nonceForVerify := ProofNonce{Fr: nonce}

	_, err := VerifySignaturePoK(&proofRequest, &signatureProof, &nonceForVerify)

	if err != nil {
		response.Verified = false
		response.Error = fmt.Sprintf("Verification failed: %v", err)
		return response, err
	}

	response.Verified = true
	return response, nil
}

func (proof *PoKOfSignatureProof) GetRespForMessage(msgIdx int) (*SignatureMessage, error) {
	// 2 elements in proofVC2.Responses are reserved for `&signature.e` and `r2`
	if msgIdx >= len(proof.ProofVC2.Responses)-2 {
		return nil, fmt.Errorf("message index was given %d but should be less than %d", msgIdx, len(proof.ProofVC2.Responses)-2)
	}
	// 2 added to the index, since 0th and 1st index are reserved for `&signature.e` and `r2`
	return &SignatureMessage{value: proof.ProofVC2.Responses[2+msgIdx]}, nil
}

func IsPointZero(point *bls12381.PointG1) bool {
	g1 := bls12381.NewG1()
	return g1.IsZero(point)
}

func SubPoint(point1, point2 *bls12381.PointG1) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	g1.Sub(point1, point1, point2)
	return point1
}

func NegatePoint(point *bls12381.PointG1) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	emptyPoint := bls12381.PointG1{}
	negPoint := g1.Neg(&emptyPoint, point)
	return negPoint
}

func (proof *PoKOfSignatureProof) Verify(vk *fhks_bbs_plus.PublicKey, revealedMsgs map[int]SignatureMessage, challenge *ProofChallenge) (PoKOfSignatureProofStatus, error) {
	if err := vk.Validate(); err != nil {
		return BadSignature, err
	}

	for i := range revealedMsgs {
		if i >= len(vk.H) {
			return BadSignature, fmt.Errorf("index %d should be less than %d", i, len(vk.H))
		}
	}

	if IsPointZero(&proof.APrime) {
		return BadSignature, nil
	}

	g1 := bls12381.NewG1()

	aBarNeg := g1.New()
	aBarNeg = g1.Neg(aBarNeg, &proof.ABar)

	pairingCheck := bls12381.NewEngine()
	pairingCheck.AddPair(&proof.APrime, vk.W)
	pairingCheck.AddPair(aBarNeg, bls12381.NewG2().One())

	if !pairingCheck.Check() {
		return BadSignature, nil
	}

	bases := []bls12381.PointG1{proof.APrime, *vk.H0}

	aBarD := g1.New()
	g1.Sub(aBarD, &proof.ABar, &proof.D)

	verified, err := proof.ProofVC1.Verify(bases, aBarD, challenge)
	if err != nil {
		return BadHiddenMessage, fmt.Errorf("verification failed: %v", err)
	}

	if !verified {
		return BadHiddenMessage, nil
	}

	basesPokVC2 := make([]bls12381.PointG1, 0, 2+len(vk.H)-len(revealedMsgs))
	basesPokVC2 = append(basesPokVC2, proof.D)
	basesPokVC2 = append(basesPokVC2, *vk.H0)

	basesDisclosed := []bls12381.PointG1{*bls12381.NewG1().One()}
	exponents := []*bls12381.Fr{bls12381.NewFr().One()}

	for i := 0; i < len(vk.H); i++ {
		if msg, found := revealedMsgs[i]; found {
			basesDisclosed = append(basesDisclosed, *vk.H[i])
			exponents = append(exponents, msg.value)
		} else {
			basesPokVC2 = append(basesPokVC2, *vk.H[i])
		}
	}

	posPr := MultiScalarMulConstTimeG1(basesDisclosed, exponents)

	negPr := g1.New()
	negPr = g1.Neg(negPr, &posPr)

	verifiedVC2, err := proof.ProofVC2.Verify(basesPokVC2, negPr, challenge)
	if err != nil {
		return BadRevealedMessage, fmt.Errorf("verification of ProofVC2 failed: %v", err)
	}

	if !verifiedVC2 {
		return BadRevealedMessage, nil
	}

	return Success, nil
}

func NewPoKOfSignatureProofWrapper(messageCount int, revealedSet map[int]struct{}, proof *PoKOfSignatureProof) *PoKOfSignatureProofWrapper {
	// Create a bit vector with message count as a 2-byte big-endian value
	bitVector := make([]byte, 2)
	binary.BigEndian.PutUint16(bitVector, uint16(messageCount))

	// Append revealed bit vector
	revealedBitVector := RevealedToBitVector(messageCount, revealedSet)
	bitVector = append(bitVector, revealedBitVector...)

	return &PoKOfSignatureProofWrapper{
		BitVector: bitVector,
		Proof:     proof,
	}
}

func (wrapper *PoKOfSignatureProofWrapper) Unwrap() (map[int]struct{}, *PoKOfSignatureProof) {
	revealedSet := BitvectorToRevealed(wrapper.BitVector[2:])
	return revealedSet, wrapper.Proof
}

func (wrapper *PoKOfSignatureProofWrapper) ToBytes() ([]byte, error) {
	data := make([]byte, len(wrapper.BitVector))
	copy(data, wrapper.BitVector)

	proofBytes, err := wrapper.Proof.ToBytesUncompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %v", err)
	}

	data = append(data, proofBytes...)
	return data, nil
}

func getB(sig fhks_bbs_plus.ThresholdSignature, messages []SignatureMessage, verkey fhks_bbs_plus.PublicKey) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	bases := []*bls12381.PointG1{g1.One()}
	scalars := []*bls12381.Fr{new(bls12381.Fr).One()}

	bases = append(bases, verkey.H0)
	scalars = append(scalars, sig.S)

	for i := 0; i < verkey.MessageCount(); i++ {
		bases = append(bases, verkey.H[i])
		scalars = append(scalars, messages[i].value)
	}

	return multiScalarMulVarTimeG1(bases, scalars)
}

func multiScalarMulVarTimeG1(bases []*bls12381.PointG1, scalars []*bls12381.Fr) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	result := g1.Zero()

	for i := range bases {
		temp := g1.New()
		g1.MulScalar(temp, bases[i], scalars[i])
		g1.Add(result, result, temp)
	}

	return result
}

func (b *BlindSignature) New(rng *rand.Rand, commitment bls12381.PointG1, messages [][]byte, signkey *bls12381.Fr, verkey fhks_bbs_plus.PublicKey) (BlindSignature, error) {

	if len(messages) > verkey.MessageCount() {
		return BlindSignature{}, nil
	}

	e := bls12381.NewFr()
	_, err := e.Rand(rng)
	if err != nil {
		panic(err)
	}

	s := bls12381.NewFr()
	_, err = s.Rand(rng)
	if err != nil {
		panic(err)
	}
	points := make([]bls12381.PointG1, 0, len(messages)+2)
	scalars := make([]*bls12381.Fr, 0, len(messages)+2)

	gOne := bls12381.NewG1().One()
	verkeyGen := verkey.H0

	points = append(points, commitment)
	scalars = append(scalars, bls12381.NewFr().One())
	points = append(points, *gOne)
	scalars = append(scalars, bls12381.NewFr().One())
	points = append(points, *verkeyGen)
	scalars = append(scalars, s)

	for i, m := range messages {
		points = append(points, *verkey.H[i])
		cloned := make([]byte, len(m))

		copy(cloned, m)
		fr := &bls12381.Fr{}

		scalars = append(scalars, fr.FromBytes(cloned))
	}

	bPoint := MultiScalarMulConstTimeG1(points, scalars)

	exp := new(bls12381.Fr).Set(signkey)
	exp.Add(exp, e)

	expInv := new(bls12381.Fr)
	expInv.Inverse(exp)

	var bPointMul bls12381.PointG1
	bls12381.NewG1().MulScalar(&bPointMul, &bPoint, expInv)

	return BlindSignature{A: &bPointMul, e: e, s: s}, nil

}

func MultiScalarMulConstTimeG1(bases []bls12381.PointG1, scalars []*bls12381.Fr) bls12381.PointG1 {
	if len(bases) != len(scalars) {
		panic("bases and scalars must have the same length")
	}

	// var result bls12381.PointG1
	result := *bls12381.NewG1().Zero()

	for i, base := range bases {
		var temp bls12381.PointG1
		// Perform scalar multiplication: temp = base * scalars[i]
		bls12381.NewG1().MulScalar(&temp, &base, scalars[i])
		// Accumulate the result: result = result + temp
		bls12381.NewG1().Add(&result, &result, &temp)
	}

	return result
}

func convertToFrArray(sigMessages []SignatureMessage) []*bls12381.Fr {
	frArray := make([]*bls12381.Fr, len(sigMessages))
	for i, msg := range sigMessages {
		frArray[i] = msg.value
	}
	return frArray
}

func NewPoKOfSignature(signature fhks_bbs_plus.ThresholdSignature, vk fhks_bbs_plus.PublicKey, messages []ProofMessage) (*PoKOfSignature, error) {
	if len(messages) != vk.MessageCount() {
		return nil, errors.New("public key generator message count mismatch")
	}

	sigMessages := make([]SignatureMessage, len(messages))
	for i, m := range messages {
		if m.Revealed != nil {
			sigMessages[i] = *m.Revealed
		} else if m.Hidden != nil && m.Hidden.ProofSpecific != nil {
			sigMessages[i] = m.Hidden.ProofSpecific.Signature
		} else if m.Hidden != nil && m.Hidden.External != nil {
			sigMessages[i] = m.Hidden.External.Signature
		}
	}

	frArray := convertToFrArray(sigMessages)

	if !signature.Verify(frArray, &vk) {
		return nil, errors.New("the messages and signature do not match")
	}

	// this generates a random Fr value
	r1 := fhks_bbs_plus.GenerateRandomFr()
	r2 := fhks_bbs_plus.GenerateRandomFr()

	temp := make([]SignatureMessage, len(messages))
	for i, msg := range messages {
		if msg.Revealed != nil {
			temp[i] = *msg.Revealed
		} else if msg.Hidden != nil && msg.Hidden.ProofSpecific != nil {
			temp[i] = msg.Hidden.ProofSpecific.Signature
		} else if msg.Hidden != nil && msg.Hidden.External != nil {
			temp[i] = msg.Hidden.External.Signature
		}
	}

	fmt.Println("temp: ", temp)

	b := getB(signature, temp, vk)

	g1 := bls12381.NewG1()

	aPrime := g1.New()
	g1.MulScalar(aPrime, signature.CapitalA, r1)

	fmt.Println("aPrime: ", aPrime)

	aBarDenom := g1.New()
	g1.MulScalar(aBarDenom, aPrime, signature.E)

	aBar := g1.New()
	g1.MulScalar(aBar, b, r1)
	g1.Sub(aBar, aBar, aBarDenom)

	r2D := new(bls12381.Fr)
	r2D.Neg(r2)
	builder := NewCommitmentBuilder()
	builder.Add(*b, r1)
	builder.Add(*vk.H0, r2D)

	d := builder.Finalize()

	r3 := new(bls12381.Fr)
	r3.Inverse(r1)

	sPrime := new(bls12381.Fr)
	sPrime.Mul(r2, r3)
	sPrime.Neg(sPrime)
	sPrime.Add(sPrime, signature.S)

	proofVC1 := NewProverCommittingG1()

	negE := new(bls12381.Fr)
	negE.Neg(signature.E)

	secrets1 := []*bls12381.Fr{
		negE,
		r2,
	}
	proofVC1.Commit(aPrime)
	proofVC1.Commit(vk.H0)

	proofVC2 := NewProverCommittingG1()

	negR3 := new(bls12381.Fr)
	negR3.Neg(r3)

	secrets2 := []*bls12381.Fr{
		negR3,
		sPrime,
	}

	proofVC2.Commit((*bls12381.PointG1)(&d))
	proofVC2.Commit(vk.H0)

	revealedMessages := make(map[int]SignatureMessage)

	for i := 0; i < vk.MessageCount(); i++ {
		if messages[i].Revealed != nil {
			revealedMessages[i] = *messages[i].Revealed
		} else if messages[i].Hidden != nil && messages[i].Hidden.ProofSpecific != nil {
			proofVC2.Commit(vk.H[i])
			secrets2 = append(secrets2, messages[i].Hidden.ProofSpecific.Signature.value)
		} else if messages[i].Hidden != nil && messages[i].Hidden.External != nil {
			proofVC2.CommitWith(vk.H[i], messages[i].Hidden.External.Nonce.Fr)
			secrets2 = append(secrets2, messages[i].Hidden.External.Signature.value)
		}
	}

	fmt.Println("revealedMessages: ", revealedMessages)
	fmt.Println("secrets1: ", secrets1)
	fmt.Println("secrets2: ", secrets2)

	finishedVC1 := proofVC1.Finish()
	finishedVC2 := proofVC2.Finish()
	return &PoKOfSignature{
		APrime:   *aPrime,
		ABar:     *aBar,
		D:        bls12381.PointG1(d),
		ProofVC1: finishedVC1,
		ProofVC2: finishedVC2,
		Secrets1: secrets1,
		Secrets2: secrets2,
		Revealed: revealedMessages,
	}, nil

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
		APrime:   pok.APrime,
		ABar:     pok.ABar,
		D:        pok.D,
		ProofVC1: *proofVC1,
		ProofVC2: *proofVC2,
	}, nil
}

func (proof *ProofG1) ToBytesUncompressedForm() ([]byte, error) {
	var bytes []byte

	afnCommitment := bls12381.NewG1().Affine(&proof.Commitment)

	// Serialize Commitment (bls12381.PointG1) in uncompressed form
	commitmentBytes := bls12381.NewG1().ToUncompressed(afnCommitment)
	bytes = append(bytes, commitmentBytes...)

	// Serialize Responses ([]*bls12381.Fr)
	for _, response := range proof.Responses {
		responseBytes := response.ToBytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes, nil
}

func (proof *ProofG1) ToBytes() ([]byte, error) {
	var bytes []byte

	// Serialize Commitment (bls12381.PointG1)
	commitmentBytes := bls12381.NewG1().ToUncompressed(&proof.Commitment)
	bytes = append(bytes, commitmentBytes...)

	// Serialize Responses ([]*bls12381.Fr)
	for _, response := range proof.Responses {
		responseBytes := response.ToBytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes, nil
}

func (proof *ProofG1) GenProof(challenge *ProofChallenge, secrets []SignatureMessage) (*ProofG1, error) {
	if len(secrets) != len(proof.Responses) {
		return nil, fmt.Errorf("unequal number of responses (%d) and secrets (%d)", len(proof.Responses), len(secrets))
	}

	newResponses := make([]*bls12381.Fr, len(proof.Responses))

	for i := 0; i < len(proof.Responses); i++ {
		// Compute challenge * secret_i
		c := new(bls12381.Fr)
		c.Set(challenge.Fr)
		c.Mul(c, secrets[i].value)

		// Compute blinding_factor_i - challenge * secret_i
		s := new(bls12381.Fr).Set(proof.Responses[i])
		s.Sub(s, c)

		newResponses[i] = s
	}

	return &ProofG1{
		Commitment: proof.Commitment,
		Responses:  newResponses,
	}, nil
}

func (pcg *ProverCommittedG1) ToBytes() ([]byte, error) {
	var bytes []byte

	// Serialize each base (assuming each base is a PointG1)
	for _, base := range pcg.Bases {
		baseBytes := bls12381.NewG1().ToUncompressed(&base)
		bytes = append(bytes, baseBytes...)
	}

	// Serialize the commitment (assuming commitment is a PointG1)
	commitmentBytes := bls12381.NewG1().ToUncompressed(&pcg.Commitment)
	bytes = append(bytes, commitmentBytes...)

	return bytes, nil
}

func (pcg *ProverCommittedG1) GenProof(challenge *ProofChallenge, secrets []SignatureMessage) (*ProofG1, error) {
	if len(secrets) != len(pcg.Bases) {
		return nil, fmt.Errorf("unequal number of bases (%d) and secrets (%d)", len(pcg.Bases), len(secrets))
	}

	responses := make([]*bls12381.Fr, len(pcg.Bases))

	for i := 0; i < len(pcg.Bases); i++ {
		// Compute c * secret_i
		c := new(bls12381.Fr).Set(challenge.Fr)
		c.Mul(c, secrets[i].value)

		// Compute blinding_factor_i - c * secret_i
		s := new(bls12381.Fr).Set(pcg.BlindingFactors[i])
		s.Sub(s, c)

		responses[i] = s
	}

	return &ProofG1{
		Commitment: pcg.Commitment,
		Responses:  responses,
	}, nil
}

func (pok *PoKOfSignature) ToBytes() ([]byte, error) {
	var bytes []byte
	aBarBytes := bls12381.NewG1().ToUncompressed(&pok.ABar)
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

func (pok *PoKOfSignatureProof) ToBytesOld() ([]byte, error) {
	var bytes []byte

	// Serialize APrime (bls12381.PointG1)
	aPrimeBytes := bls12381.NewG1().ToUncompressed(&pok.APrime)
	bytes = append(bytes, aPrimeBytes...)

	// Serialize ABar (bls12381.PointG1)
	aBarBytes := bls12381.NewG1().ToUncompressed(&pok.ABar)
	bytes = append(bytes, aBarBytes...)

	// Serialize D (bls12381.PointG1)
	dBytes := bls12381.NewG1().ToUncompressed(&pok.D)
	bytes = append(bytes, dBytes...)

	// Serialize ProofVC1 (ProofG1)
	proofVC1Bytes, err := pok.ProofVC1.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC1: %v", err)
	}
	bytes = append(bytes, proofVC1Bytes...)

	// Serialize ProofVC2 (ProofG1)
	proofVC2Bytes, err := pok.ProofVC2.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC2: %v", err)
	}
	bytes = append(bytes, proofVC2Bytes...)

	return bytes, nil
}

type PoKOfSignature struct {
	APrime   bls12381.PointG1
	ABar     bls12381.PointG1
	D        bls12381.PointG1
	ProofVC1 ProverCommittedG1
	ProofVC2 ProverCommittedG1
	Secrets1 []*bls12381.Fr
	Secrets2 []*bls12381.Fr
	Revealed map[int]SignatureMessage
}

func (proof *PoKOfSignatureProof) GetBytesForChallenge(revealedMsgIndices map[int]struct{}, vk *fhks_bbs_plus.PublicKey) ([]byte, error) {
	var bytes []byte

	// Serialize ABar, APrime, and D in compressed form
	aBarBytes := bls12381.NewG1().ToUncompressed(&proof.ABar)
	bytes = append(bytes, aBarBytes...)

	aPrimeBytes := bls12381.NewG1().ToUncompressed(&proof.APrime)
	bytes = append(bytes, aPrimeBytes...)

	// Serialize H0 (public key component) in uncompressed form
	h0Bytes := bls12381.NewG1().ToUncompressed(vk.H0)
	bytes = append(bytes, h0Bytes...)

	// Serialize ProofVC1 commitment in uncompressed form

	proofVC1Bytes := bls12381.NewG1().ToUncompressed(&proof.ProofVC1.Commitment)

	bytes = append(bytes, proofVC1Bytes...)

	dBytes := bls12381.NewG1().ToUncompressed(&proof.D)
	bytes = append(bytes, dBytes...)

	// for some reason, second time serialization of h0 is necessary as per original code
	bytes = append(bytes, h0Bytes...)

	// Serialize each unrevealed message's corresponding public key generator H[i]
	for i := 0; i < len(vk.H); i++ {
		if _, revealed := revealedMsgIndices[i]; !revealed {
			hBytes := bls12381.NewG1().ToUncompressed(vk.H[i])
			bytes = append(bytes, hBytes...)
		}
	}

	// Serialize ProofVC2 commitment in uncompressed form

	proofVC2Bytes := bls12381.NewG1().ToUncompressed(&proof.ProofVC2.Commitment)

	bytes = append(bytes, proofVC2Bytes...)

	return bytes, nil
}

func (proof *PoKOfSignatureProof) ToBytesUncompressedForm() ([]byte, error) {
	var bytes []byte

	// Serialize ABar (bls12381.PointG1) in compressed form
	aBarBytes := bls12381.NewG1().ToUncompressed(&proof.ABar)
	bytes = append(bytes, aBarBytes...)
	fmt.Println("ABar compressed length:", len(aBarBytes)) // Prints 48 bytes

	// Serialize APrime (bls12381.PointG1) in compressed form
	aPrimeBytes := bls12381.NewG1().ToUncompressed(&proof.APrime)
	bytes = append(bytes, aPrimeBytes...)
	fmt.Println("APrime compressed length:", len(aPrimeBytes)) // Prints 48 bytes

	// Serialize D (bls12381.PointG1) in compressed form
	dBytes := bls12381.NewG1().ToUncompressed(&proof.D)
	bytes = append(bytes, dBytes...)
	fmt.Println("D compressed length:", len(dBytes)) // Prints 48 bytes

	// Serialize ProofVC1 (assuming ProofVC1 has its own ToBytesCompressedForm method)
	proofVC1Bytes, err := proof.ProofVC1.ToBytesUncompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC1: %v", err)
	}
	bytes = append(bytes, proofVC1Bytes...)
	fmt.Println("ProofVC1 compressed length:", len(proofVC1Bytes)) // Should print 112 bytes

	// Serialize ProofVC2 (assuming ProofVC2 has its own ToBytesCompressedForm method)
	proofVC2Bytes, err := proof.ProofVC2.ToBytesUncompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC2: %v", err)
	}
	bytes = append(bytes, proofVC2Bytes...)
	fmt.Println("ProofVC2 compressed length:", len(proofVC2Bytes)) // Should print 112 bytes

	fmt.Println("Total compressed length:", len(bytes)) // Should print 368 bytes
	return bytes, nil
}

type CommitmentBuilder struct {
	bases   []bls12381.PointG1
	scalars []*bls12381.Fr
}

// NewCommitmentBuilder initializes a new CommitmentBuilder
func NewCommitmentBuilder() *CommitmentBuilder {
	return &CommitmentBuilder{
		bases:   make([]bls12381.PointG1, 0),
		scalars: make([]*bls12381.Fr, 0),
	}
}

// Add adds a new base and scalar to the commitment
func (cb *CommitmentBuilder) Add(base bls12381.PointG1, scalar *bls12381.Fr) {
	cb.bases = append(cb.bases, base)
	cb.scalars = append(cb.scalars, scalar)
}

func (cb *CommitmentBuilder) Finalize() Commitment {
	return Commitment(MultiScalarMulConstTimeG1(cb.bases, cb.scalars))
}

type CreateProofRequest struct {
	Signature fhks_bbs_plus.ThresholdSignature
	PublicKey fhks_bbs_plus.PublicKey
	Messages  [][]byte
	Revealed  []int
	Nonce     []byte
}

func CreateProofBBS(req CreateProofRequest) (*PoKOfSignatureProofWrapper, []byte, error) {
	// Step 1: Handle revealed messages
	revealedSet := make(map[int]struct{})
	for _, r := range req.Revealed {
		if r >= len(req.PublicKey.H) {
			return nil, nil, fmt.Errorf("revealed value is out of bounds")
		}
		revealedSet[r] = struct{}{}
	}

	hashMsgs := make([]*bls12381.Fr, len(req.Messages))
	for i, msg := range req.Messages {
		hashMsgs[i] = helper.HashToFr(msg)
	}

	// Step 2: Prepare messages (either revealed or hidden)

	messages, _, err := ProcessMessages(req.Messages, req.Revealed, len(req.PublicKey.H))

	for i, message := range messages {
		if message.Revealed != nil {
			fmt.Printf("Index %d: Revealed message - %x\n", i, message.Revealed.value.ToBytes())
		} else if message.Hidden != nil {
			fmt.Printf("Index %d: Hidden message - %x\n", i, message.Hidden.ProofSpecific.Signature.value.ToBytes())
		}
	}

	// Step 3: Initialize PoK of Signature Proof

	if !req.PublicKey.Verify(hashMsgs, &req.Signature) {
		return nil, nil, errors.New("the messages and signature do not match req.PublicKey.Verify")
	}

	pok, err := NewPoKOfSignature(req.Signature, req.PublicKey, messages)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize PoKOfSignature: %v", err)
	}

	// Step 4: Generate challenge bytes
	challengeBytes, err := pok.ToBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize PoKOfSignature: %v", err)
	}

	if len(req.Nonce) == 0 {
		challengeBytes = append(challengeBytes, make([]byte, helper.FR_UNCOMPRESSED_SIZE)...)
	} else {
		nonce := helper.HashToFr(req.Nonce).ToBytes()
		challengeBytes = append(challengeBytes, nonce...)
	}

	challenge := &ProofChallenge{Fr: helper.HashToFr(challengeBytes)}

	// Step 5: Generate final proof
	proof, err := pok.GenProof(challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	out := NewPoKOfSignatureProofWrapper(req.PublicKey.MessageCount(), revealedSet, proof)

	outBytes, err := out.ToBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert proof wrapper to bytes: %v", err)
	}

	return out, outBytes, nil
}
func ProcessMessages(reqMessages [][]byte, revealedIndices []int, publicKeyLength int) ([]ProofMessage, map[int]struct{}, error) {
	var messages []ProofMessage

	// Step 1: Validate and build the revealedSet from revealedIndices
	revealedSet := make(map[int]struct{})
	for _, r := range revealedIndices {
		if r >= publicKeyLength {
			return nil, nil, fmt.Errorf("revealed value %d is out of bounds", r)
		}
		revealedSet[r] = struct{}{}
	}

	// Step 2: Process each message and categorize it as revealed or hidden
	for i, msg := range reqMessages {
		hashedMsg := SignatureMessage{value: helper.HashToFr(msg)}
		if _, found := revealedSet[i]; found {
			messages = append(messages, ProofMessage{
				Revealed: &hashedMsg,
			})
		} else {
			messages = append(messages, ProofMessage{
				Hidden: &HiddenMessage{
					ProofSpecific: &ProofSpecificBlinding{
						Signature: hashedMsg,
					},
				},
			})
		}
	}

	return messages, revealedSet, nil
}
