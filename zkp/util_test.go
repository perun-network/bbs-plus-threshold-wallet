package zkp_test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRevealedToBitVector(t *testing.T) {
	revealedSet := map[int]struct{}{0: {}, 9: {}} // Revealing messages at index 0 and 9
	bitVector := zkp.RevealedToBitVector(10, revealedSet)

	expectedBitVector := []byte{0b00000010, 0b00000001} // Expected big-endian result
	if !equal(expectedBitVector, bitVector) {
		t.Errorf("bit vector mismatch: expected %08b but got %08b", expectedBitVector, bitVector)
	}
}

// Helper function to compare two byte slices
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBitvectorToRevealed(t *testing.T) {
	bitVector := []byte{0b00000001, 0b00000010}
	revealedSet := zkp.BitvectorToRevealed(bitVector)
	expectedSet := map[int]struct{}{1: {}, 8: {}}
	assert.Equal(t, expectedSet, revealedSet, "revealed set mismatch")
}
