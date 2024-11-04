package zkp

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
)

type Commitment bls12381.PointG1

func BitvectorToRevealed(bitVector []byte) map[int]struct{} {
	revealedSet := make(map[int]struct{})
	for i := 0; i < len(bitVector)*8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if (bitVector[byteIndex] & (1 << bitIndex)) != 0 {
			revealedSet[i] = struct{}{}
		}
	}
	return revealedSet
}

func RevealedToBitVector(messageCount int, revealedSet map[int]struct{}) []byte {
	bitVector := make([]byte, (messageCount+7)/8) // Create a bit vector of appropriate size
	for index := range revealedSet {
		byteIndex := index / 8
		bitIndex := index % 8
		bitVector[byteIndex] |= (1 << bitIndex)
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

	randFactor := fhks_bbs_plus.GenerateSecretKey()
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
