package zkp

import (
	"encoding/binary"
	"errors"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"golang.org/x/crypto/blake2b"
	"math/rand"
)

const FR_COMPRESSED_SIZE = 32

type BlindSignature struct {
	A *bls12381.PointG1
	e *bls12381.Fr
	s *bls12381.Fr
}

type PoKOfSignatureProofWrapper struct {
	BitVector []byte
	Proof     *PoKOfSignatureProof
}

type SignatureBlinding struct {
	*bls12381.Fr
}

type ProofSpecificBlinding struct {
	Signature SignatureMessage
}

type ProofG1 struct {
	Commitment bls12381.PointG1 // The proof commitment of all base_0*exp_0+base_1*exp_1...
	Responses  []*bls12381.Fr   // s values in the Fiat-Shamir protocol
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

// ProofMessage represents a proof message which can be revealed or hidden
type ProofMessage struct {
	Revealed *SignatureMessage
	Hidden   *HiddenMessage
}

type SignatureMessage struct {
	value *bls12381.Fr
}

func (msg *SignatureMessage) Get() *bls12381.Fr {
	return msg.value
}

func (msg *SignatureMessage) Set(value *bls12381.Fr) {
	msg.value = value
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

	proofBytes, err := wrapper.Proof.ToBytesCompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %v", err)
	}

	data = append(data, proofBytes...)
	return data, nil
}

func getB(messages []SignatureMessage, verkey fhks_bbs_plus.PublicKey) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	bases := []*bls12381.PointG1{g1.One()}
	scalars := []*bls12381.Fr{new(bls12381.Fr).One()}

	bases = append(bases, verkey.H0)
	scalars = append(scalars, messages[0].value) // Assuming signatureS is the first message for simplicity

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

func HashToFr(data []byte) *bls12381.Fr {
	const FR_UNCOMPRESSED_SIZE = 32 // Adjust this size based on your requirements
	// Create a new BLAKE2b hash with the desired output size
	// hasher, err := blake2.New(FR_UNCOMPRESSED_SIZE, nil)
	hasher, err := blake2b.New(FR_UNCOMPRESSED_SIZE, nil)
	if err != nil {
		panic(err)
	}

	// Write data to the hasher
	hasher.Write(data)

	// Get the hash result
	res := hasher.Sum(nil)

	// Convert the hash result to an Fr element
	fr := &bls12381.Fr{}
	fr.FromBytes(res)

	return fr
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

	var result bls12381.PointG1
	result.Zero() // Initialize result to the identity element

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

func NewPoKOfSignatureProof(signature fhks_bbs_plus.ThresholdSignature, vk fhks_bbs_plus.PublicKey, messages []ProofMessage) (*PoKOfSignatureProof, error) {
	if len(messages) != len(vk.H) {
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
	r1 := fhks_bbs_plus.GenerateSecretKey()
	r2 := fhks_bbs_plus.GenerateSecretKey()

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

	b := getB(temp, vk)

	g1 := bls12381.NewG1()

	aPrime := g1.New()
	g1.MulScalar(aPrime, signature.CapitalA, r1)

	aBarDenom := g1.New()
	g1.MulScalar(aBarDenom, aPrime, signature.E)

	aBar := g1.New()
	g1.MulScalar(aBar, b, r1)
	g1.Sub(aBar, aBar, aBarDenom)

	r2D := new(bls12381.Fr)
	r2D.Neg(r2)
	builder := NewCommitmentBuilder()
	builder.Add(*vk.H0, r2D)
	builder.Add(*b, r1)

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

	proofVC1.Commit(vk.H0)
	proofVC1.Commit(aPrime)

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
	finishedVC1 := proofVC1.Finish()
	finishedVC2 := proofVC2.Finish()
	return &PoKOfSignatureProof{
		APrime:   *aPrime,
		ABar:     *aBar,
		D:        bls12381.PointG1(d),
		ProofVC1: ProofG1{Commitment: finishedVC1.Commitment, Responses: secrets1},
		ProofVC2: ProofG1{Commitment: finishedVC2.Commitment, Responses: secrets2},
		Secrets1: secrets1,
		Secrets2: secrets2,
		Revealed: revealedMessages,
	}, nil

}

func (pok *PoKOfSignatureProof) GenProof(challengeHash *ProofChallenge) (*PoKOfSignatureProof, error) {
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

func (proof *ProofG1) ToBytesCompressedForm() ([]byte, error) {
	var bytes []byte

	// Serialize Commitment (bls12381.PointG1) in compressed form
	commitmentBytes := bls12381.NewG1().ToCompressed(&proof.Commitment)
	bytes = append(bytes, commitmentBytes...)

	// Serialize Responses ([]*bls12381.Fr)
	for _, response := range proof.Responses {
		responseBytes := response.ToBytes() // Assuming Fr has ToBytes() method
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

func (pok *PoKOfSignatureProof) ToBytes() ([]byte, error) {
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

type PoKOfSignatureProof struct {
	APrime   bls12381.PointG1
	ABar     bls12381.PointG1
	D        bls12381.PointG1
	ProofVC1 ProofG1
	ProofVC2 ProofG1
	Secrets1 []*bls12381.Fr
	Secrets2 []*bls12381.Fr
	Revealed map[int]SignatureMessage
}

func (proof *PoKOfSignatureProof) ToBytesCompressedForm() ([]byte, error) {
	var bytes []byte

	// Serialize APrime (bls12381.PointG1) in compressed form
	aPrimeBytes := bls12381.NewG1().ToCompressed(&proof.APrime)
	bytes = append(bytes, aPrimeBytes...)
	fmt.Println("APrime compressed length:", len(aPrimeBytes)) // Prints 48 bytes

	// Serialize ABar (bls12381.PointG1) in compressed form
	aBarBytes := bls12381.NewG1().ToCompressed(&proof.ABar)
	bytes = append(bytes, aBarBytes...)
	fmt.Println("ABar compressed length:", len(aBarBytes)) // Prints 48 bytes

	// Serialize D (bls12381.PointG1) in compressed form
	dBytes := bls12381.NewG1().ToCompressed(&proof.D)
	bytes = append(bytes, dBytes...)
	fmt.Println("D compressed length:", len(dBytes)) // Prints 48 bytes

	// Serialize ProofVC1 (assuming ProofVC1 has its own ToBytesCompressedForm method)
	proofVC1Bytes, err := proof.ProofVC1.ToBytesCompressedForm()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProofVC1: %v", err)
	}
	bytes = append(bytes, proofVC1Bytes...)
	fmt.Println("ProofVC1 compressed length:", len(proofVC1Bytes)) // Should print 112 bytes

	// Serialize ProofVC2 (assuming ProofVC2 has its own ToBytesCompressedForm method)
	proofVC2Bytes, err := proof.ProofVC2.ToBytesCompressedForm()
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

func createProofBBS(req CreateProofRequest) ([]byte, error) {
	// Step 1: Handle revealed messages
	revealedSet := make(map[int]struct{})
	for _, r := range req.Revealed {
		if r >= len(req.PublicKey.H) {
			return nil, fmt.Errorf("revealed value is out of bounds")
		}
		revealedSet[r] = struct{}{}
	}

	// Step 2: Prepare messages (either revealed or hidden)
	var messages []ProofMessage
	for i, msg := range req.Messages {
		hashedMsg := SignatureMessage{value: HashToFr(msg)} // Correct field name: Value
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

	// Step 3: Initialize PoK of Signature Proof
	pok, err := NewPoKOfSignatureProof(req.Signature, req.PublicKey, messages)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PoKOfSignature: %v", err)
	}

	// Step 4: Generate challenge bytes
	challengeBytes, err := pok.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PoKOfSignature: %v", err)
	}

	if len(req.Nonce) == 0 {
		challengeBytes = append(challengeBytes, make([]byte, FR_COMPRESSED_SIZE)...)
	} else {
		nonce := HashToFr(req.Nonce).ToBytes() // Hash the nonce and convert to bytes
		challengeBytes = append(challengeBytes, nonce...)
	}

	challenge := &ProofChallenge{Fr: HashToFr(challengeBytes)}

	// Step 5: Generate final proof
	proof, err := pok.GenProof(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	out := NewPoKOfSignatureProofWrapper(req.PublicKey.MessageCount(), revealedSet, proof)

	return out.ToBytes()
}
