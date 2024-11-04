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

	response1 := fhks_bbs_plus.GenerateSecretKey()
	response2 := fhks_bbs_plus.GenerateSecretKey()

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

func TestProofG1_ToBytesCompressedForm(t *testing.T) {
	proof := createSampleProofG1()

	bytes, err := proof.ToBytesCompressedForm()

	assert.NoError(t, err, "Error when encoding to compressed bytes")
	assert.NotNil(t, bytes, "compressed encoded bytes should not be nil")

	expectedLength := 48 + len(proof.Responses)*32 // Adjust based on actual sizes
	assert.Equal(t, expectedLength, len(bytes), "compressed encoded bytes length mismatch")
}

func TestPoKOfSignatureProof_ToBytes(t *testing.T) {
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

	bytes, err := pok.ToBytes()

	assert.NoError(t, err, "error when encoding PoKOfSignatureProof to bytes")
	assert.NotNil(t, bytes, "encoded PoKOfSignatureProof bytes should not be nil")

	expectedLength := 288 + 192 + len(proofVC1.Responses)*32*2 // Adjust based on actual sizes
	assert.Equal(t, expectedLength, len(bytes), "Encoded PoKOfSignatureProof bytes length mismatch")
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

	bytes, err := pok.ToBytesCompressedForm()

	assert.NoError(t, err, "error when encoding PoKOfSignatureProof to compressed form")
	assert.NotNil(t, bytes, "compressed encoded PoKOfSignatureProof bytes should not be nil")

	// Breakdown of the expected length:
	// - APrime (compressed G1 point): 48 bytes
	// - ABar (compressed G1 point): 48 bytes
	// - D (compressed G1 point): 48 bytes
	// - ProofVC1:
	//   - Commitment (compressed G1 point): 48 bytes
	//   - Responses (2 Fr elements at 32 bytes each): 64 bytes
	//   Total for ProofVC1: 48 + 64 = 112 bytes
	// - ProofVC2:
	//   - Commitment (compressed G1 point): 48 bytes
	//   - Responses (2 Fr elements at 32 bytes each): 64 bytes
	//   Total for ProofVC2: 48 + 64 = 112 bytes
	//
	// Total expected length:
	// 48 (APrime) + 48 (ABar) + 48 (D) + 112 (ProofVC1) + 112 (ProofVC2) = **368 bytes**

	expectedLength := 368
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
