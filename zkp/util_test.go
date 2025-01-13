package zkp_test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBitvectorToRevealed(t *testing.T) {
	bitVector := []byte{0b00000001, 0b00000010}
	revealedSet := zkp.BitvectorToRevealed(bitVector)
	expectedSet := map[int]struct{}{1: {}, 8: {}}
	assert.Equal(t, expectedSet, revealedSet, "revealed set mismatch")
}
