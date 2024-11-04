package zkp_test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRevealedToBitVector(t *testing.T) {
	revealedSet := map[int]struct{}{0: {}, 9: {}}
	bitVector := zkp.RevealedToBitVector(10, revealedSet)

	expectedBitVector := []byte{0b00000001, 0b00000010}
	assert.Equal(t, expectedBitVector, bitVector, "bit vector mismatch")
}

func TestBitvectorToRevealed(t *testing.T) {
	bitVector := []byte{0b00000001, 0b00000010}
	revealedSet := zkp.BitvectorToRevealed(bitVector)

	expectedSet := map[int]struct{}{0: {}, 9: {}}
	assert.Equal(t, expectedSet, revealedSet, "revealed set mismatch")
}
