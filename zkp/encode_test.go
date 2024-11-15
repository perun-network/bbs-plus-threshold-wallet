package zkp_test

import (
	"github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func createSampleProofG1() *zkp.ProofG1 {
	g1 := bls12381.NewG1()

	commitment := g1.One()

	response1 := fhks_bbs_plus.GenerateRandomFr()
	response2 := fhks_bbs_plus.GenerateRandomFr()

	return &zkp.ProofG1{
		Commitment: *commitment,
		Responses:  []*bls12381.Fr{response1, response2},
	}
}

func TestProofG1_ToBytes(t *testing.T) {
	proof := createSampleProofG1()

	bytes, err := proof.ToBytes()

	assert.NoError(t, err, "error when encoding to bytes")
	assert.NotNil(t, bytes, "encoded bytes should not be nil")

	expectedLength := 96 + len(proof.Responses)*32 // Adjust based on actual sizes
	assert.Equal(t, expectedLength, len(bytes), "encoded bytes length mismatch")
}

func TestProofG1_ToBytesUncompressedForm(t *testing.T) {
	proof := createSampleProofG1()

	bytes, err := proof.ToBytesUncompressedForm()

	assert.NoError(t, err, "Error when encoding to uncompressed bytes")
	assert.NotNil(t, bytes, "uncompressed encoded bytes should not be nil")

	// Breakdown of expected length:
	// - Commitment (uncompressed G1 point): 96 bytes
	// - Responses (2 Fr elements at 32 bytes each): 64 bytes
	//
	// Total expected length: 96 + 64 = 160 bytes
	expectedLength := 96 + len(proof.Responses)*32
	assert.Equal(t, expectedLength, len(bytes), "uncompressed encoded bytes length mismatch")
}

func TestPoKOfSignatureProof_ToBytesCompressedForm(t *testing.T) {
	g1 := bls12381.NewG1()

	proofVC1 := createSampleProofG1()
	proofVC2 := createSampleProofG1()

	pok := zkp.PoKOfSignatureProof{
		APrime:   *g1.One(),
		ABar:     *g1.One(),
		D:        *g1.One(),
		ProofVC1: *proofVC1,
		ProofVC2: *proofVC2,
	}

	bytes, err := pok.ToBytesUncompressedForm()

	assert.NoError(t, err, "error when encoding PoKOfSignatureProof to compressed form")
	assert.NotNil(t, bytes, "compressed encoded PoKOfSignatureProof bytes should not be nil")
	// Breakdown of the expected length:
	// - APrime (uncompressed G1 point): 96 bytes
	// - ABar (uncompressed G1 point): 96 bytes
	// - D (uncompressed G1 point): 96 bytes
	// - ProofVC1:
	//   - Commitment (uncompressed G1 point): 96 bytes
	//   - Responses (2 Fr elements at 32 bytes each): 64 bytes
	//   Total for ProofVC1: 96 + 64 = 160 bytes
	// - ProofVC2:
	//   - Commitment (uncompressed G1 point): 96 bytes
	//   - Responses (2 Fr elements at 32 bytes each): 64 bytes
	//   Total for ProofVC2: 96 + 64 = 160 bytes
	//
	// Total expected length:
	// 96 (APrime) +
	// 96 (ABar) +
	// 96 (D) +
	// 160 (ProofVC1) +
	// 160 (ProofVC2) =
	// **608 bytes**
	expectedLength := 608
	assert.Equal(t, expectedLength, len(bytes), "compressed encoded PoKOfSignatureProof length mismatch")
}

func TestProverCommittedG1_ToBytes(t *testing.T) {
	g1 := bls12381.NewG1()
	base := g1.One()

	pcg := zkp.NewProverCommittingG1()
	pcg.Commit(base)
	committed := pcg.Finish()

	bytes, err := committed.ToBytes()

	assert.NoError(t, err, "error serializing ProverCommittedG1 to bytes")
	assert.NotNil(t, bytes, "serialized bytes should not be nil")
}
