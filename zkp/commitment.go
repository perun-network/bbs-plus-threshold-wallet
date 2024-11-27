package zkp

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
)

type CommitmentBuilder struct {
	bases   []*bls12381.PointG1
	scalars []*bls12381.Fr
}

type ProverCommittedG1 struct {
	Bases           []*bls12381.PointG1
	BlindingFactors []*bls12381.Fr
	Commitment      *bls12381.PointG1
}

type ProverCommittingG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
}

// NewCommitmentBuilder creates a new CommitmentBuilder with an expected size
func NewCommitmentBuilder(expectedSize int) *CommitmentBuilder {
	return &CommitmentBuilder{
		bases:   make([]*bls12381.PointG1, 0, expectedSize),
		scalars: make([]*bls12381.Fr, 0, expectedSize),
	}
}

// Add adds a base point and its corresponding scalar to the CommitmentBuilder
func (cb *CommitmentBuilder) Add(base *bls12381.PointG1, scalar *bls12381.Fr) {
	cb.bases = append(cb.bases, base)
	cb.scalars = append(cb.scalars, scalar)
}

// Build performs multi-scalar multiplication on the accumulated bases and scalars
func (cb *CommitmentBuilder) Build() *bls12381.PointG1 {
	return MultiScalarMulVarTimeG1(cb.bases, cb.scalars)
}

func newVC1Signature(aPrime *bls12381.PointG1, h0 *bls12381.PointG1,
	e, r2 *bls12381.Fr) (*ProverCommittedG1, []*bls12381.Fr) {

	// Initialize prover committing object
	committing1 := NewProverCommittingG1()

	// Prepare secrets array (2 elements)
	secrets1 := make([]*bls12381.Fr, 2)

	// Commit aPrime
	committing1.Commit(aPrime)

	// Copy and negate e to create sigE
	sigE := new(bls12381.Fr).Set(e)
	sigE.Neg(sigE)
	secrets1[0] = sigE // Store negated e in secrets

	// Commit h0
	committing1.Commit(h0)

	// Store r2 in secrets
	secrets1[1] = r2

	// Finalize commitment proof
	pokVC1 := committing1.Finish()

	return pokVC1, secrets1
}

func newVC2Signature(d *bls12381.PointG1, r3 *bls12381.Fr, pubKey *fhks_bbs_plus.PublicKey, sPrime *bls12381.Fr,
	messages []*SignatureMessage, revealedMessages map[int]*SignatureMessage) (*ProverCommittedG1, []*bls12381.Fr) {

	// Initialize ProverCommittingG1 object
	committing2 := NewProverCommittingG1()

	// Prepare secrets array
	messagesCount := len(messages)
	baseSecretsCount := 2 // Base secrets include r3 and sPrime
	secrets2 := make([]*bls12381.Fr, 0, baseSecretsCount+messagesCount)

	// Commit d
	committing2.Commit(d)

	// Negate r3 and add to secrets
	negR3 := new(bls12381.Fr).Set(r3)
	negR3.Neg(negR3)
	secrets2 = append(secrets2, negR3)

	// Commit pubKey.h0 and add sPrime to secrets
	committing2.Commit(pubKey.H0)
	secrets2 = append(secrets2, sPrime)

	// Iterate through messages and commit unrevealed ones
	for i := 0; i < messagesCount; i++ {
		if _, ok := revealedMessages[i]; ok {
			continue // Skip revealed messages
		}

		// Commit pubKey.h[i]
		committing2.Commit(pubKey.H[i])

		// Copy and add hidden message to secrets
		sourceFR := messages[i].value
		hiddenFRCopy := new(bls12381.Fr).Set(sourceFR)
		secrets2 = append(secrets2, hiddenFRCopy)
	}

	// Finalize commitment proof
	pokVC2 := committing2.Finish()

	return pokVC2, secrets2
}

func (pcg *ProverCommittingG1) GetBasePoints() []*bls12381.PointG1 {
	return pcg.bases
}

func (pcg *ProverCommittingG1) GetBlindingFactors() []*bls12381.Fr {
	return pcg.blindingFactors
}

func (pcg *ProverCommittingG1) CommitWith(base *bls12381.PointG1, blindingFactor *bls12381.Fr) int {
	idx := len(pcg.bases)
	pcg.bases = append(pcg.bases, base)
	pcg.blindingFactors = append(pcg.blindingFactors, blindingFactor)

	return idx
}

func NewProverCommittingG1() *ProverCommittingG1 {
	return &ProverCommittingG1{
		bases:           make([]*bls12381.PointG1, 0),
		blindingFactors: make([]*bls12381.Fr, 0),
	}
}

// Commit adds a base point and generates a random scalar (Fr) to append to blinding factors
func (pc *ProverCommittingG1) Commit(base *bls12381.PointG1) {
	pc.bases = append(pc.bases, base)
	r := fhks_bbs_plus.GenerateRandomFr() // Generate random Fr element
	pc.blindingFactors = append(pc.blindingFactors, r)
}

// Finish computes the final commitment by performing multi-scalar multiplication
func (pc *ProverCommittingG1) Finish() *ProverCommittedG1 {
	commitment := MultiScalarMulVarTimeG1(pc.bases, pc.blindingFactors)

	return &ProverCommittedG1{
		Bases:           pc.bases,
		BlindingFactors: pc.blindingFactors,
		Commitment:      commitment,
	}
}
