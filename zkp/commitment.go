package zkp

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
)

type Commitment bls12381.PointG1

func BitvectorToRevealed(data []byte) map[int]struct{} {
	revealedMessages := make(map[int]struct{})
	scalar := 0

	// Iterate over the byte slice in reverse (big-endian interpretation)
	for i := len(data) - 1; i >= 0; i-- {
		v := data[i]   // Get the current byte
		remaining := 8 // Track remaining bits in the byte

		// Process each bit in the byte
		for v > 0 {
			revealed := v & 1 // Check if the least significant bit is set
			if revealed == 1 {
				revealedMessages[scalar] = struct{}{} // Add index to revealed set
			}
			v >>= 1     // Shift right to process the next bit
			scalar++    // Increment scalar to track bit position
			remaining-- // Decrease remaining bits count
		}
		scalar += remaining // Skip any remaining bits that are 0
	}

	return revealedMessages
}

func RevealedToBitVector(messageCount int, revealedSet map[int]struct{}) []byte {
	// Allocate enough space for the bit vector (add an extra byte like in Rust)
	bitVector := make([]byte, (messageCount/8)+1)

	// Set bits corresponding to revealed indices
	for index := range revealedSet {
		byteIndex := index / 8
		bitIndex := index % 8
		bitVector[byteIndex] |= (1 << bitIndex)
	}

	// Reverse the byte array to convert to big-endian format
	for i, j := 0, len(bitVector)-1; i < j; i, j = i+1, j-1 {
		bitVector[i], bitVector[j] = bitVector[j], bitVector[i]
	}

	return bitVector
}

type ProverCommittedG1 struct {
	Bases           []bls12381.PointG1
	BlindingFactors []*bls12381.Fr
	Commitment      bls12381.PointG1
}

type ProverCommittingG1 struct {
	bases           []bls12381.PointG1
	blindingFactors []*bls12381.Fr
}

func NewProverCommittingG1() *ProverCommittingG1 {
	return &ProverCommittingG1{
		bases:           make([]bls12381.PointG1, 0),
		blindingFactors: make([]*bls12381.Fr, 0),
	}
}

func (pcg *ProverCommittingG1) GetBasePoints() []bls12381.PointG1 {
	return pcg.bases
}

func (pcg *ProverCommittingG1) GetBlindingFactors() []*bls12381.Fr {
	return pcg.blindingFactors
}

func (pcg *ProverCommittingG1) Commit(base *bls12381.PointG1) int {
	idx := len(pcg.bases)
	pcg.bases = append(pcg.bases, *base)

	randFactor := fhks_bbs_plus.GenerateRandomFr()
	pcg.blindingFactors = append(pcg.blindingFactors, randFactor)

	return idx
}

func (pcg *ProverCommittingG1) CommitWith(base *bls12381.PointG1, blindingFactor *bls12381.Fr) int {
	idx := len(pcg.bases)
	pcg.bases = append(pcg.bases, *base)
	pcg.blindingFactors = append(pcg.blindingFactors, blindingFactor)

	return idx
}

func (pcg *ProverCommittingG1) Finish() ProverCommittedG1 {
	commitment := MultiScalarMulConstTimeG1(pcg.bases, pcg.blindingFactors)
	return ProverCommittedG1{
		Bases:           pcg.bases,
		BlindingFactors: pcg.blindingFactors,
		Commitment:      commitment,
	}
}

func (pcg *ProverCommittingG1) GetIndex(idx int) (*bls12381.PointG1, *bls12381.Fr, error) {
	if idx >= len(pcg.bases) {
		return nil, nil, fmt.Errorf("index %d greater than size %d", idx, len(pcg.bases))
	}
	return &pcg.bases[idx], pcg.blindingFactors[idx], nil
}
