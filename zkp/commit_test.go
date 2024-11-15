package zkp_test

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"

	"github.com/stretchr/testify/assert"

	"testing"
)

func TestProverCommittingG1_Commit(t *testing.T) {
	g1 := bls12381.NewG1()
	base := g1.One()

	pcg := zkp.NewProverCommittingG1()
	idx := pcg.Commit(base)

	assert.Equal(t, 0, idx, "Index should be 0 for the first commitment")
	assert.Equal(t, 1, len(pcg.GetBasePoints()), "There should be one base after commit")
	assert.NotNil(t, pcg.GetBlindingFactors(), "Blinding factor should not be nil")
}

func TestProverCommittingG1_CommitWith(t *testing.T) {
	g1 := bls12381.NewG1()
	base := g1.One()
	blindingFactor := fhks_bbs_plus.GenerateRandomFr()

	pcg := zkp.NewProverCommittingG1()
	idx := pcg.CommitWith(base, blindingFactor)

	assert.Equal(t, 0, idx, "Index should be 0 for the first commitment")
	assert.Equal(t, 1, len(pcg.GetBasePoints()), "There should be one base after commit")

	// Compare the first element of the blinding factors slice
	assert.Equal(t, blindingFactor, pcg.GetBlindingFactors()[0], "Blinding factor should match the one provided")
}

func TestProverCommittingG1_Finish(t *testing.T) {
	g1 := bls12381.NewG1()
	base := g1.One()

	pcg := zkp.NewProverCommittingG1()
	pcg.Commit(base)
	committed := pcg.Finish()

	assert.NotNil(t, committed.Commitment, "Commitment should not be nil after finish")
}
