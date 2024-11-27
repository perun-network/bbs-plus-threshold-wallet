package zkp_test

import (
	"fmt"
	"github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/test"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	zkptest "github.com/perun-network/bbs-plus-threshold-wallet/zkp/test"
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

	expectedLength := 112
	assert.Equal(t, expectedLength, len(bytes), "encoded bytes length mismatch")
}

func TestProofG1_ToBytesCompressedForm(t *testing.T) {
	proof := createSampleProofG1()

	bytes, err := proof.ToBytesCompressedForm()

	assert.NoError(t, err, "encoding to compressed bytes failed")

	expectedLength := 116
	assert.Equal(t, expectedLength, len(bytes), "compressed encoded bytes length mismatch")
}
func TestPoKOfSignatureProof_ToBytesCompressedForm(t *testing.T) {
	g1 := bls12381.NewG1()

	proofVC1 := createSampleProofG1()
	proofVC2 := createSampleProofG1()

	pok := zkp.PoKOfSignatureProof{
		APrime:   g1.One(),
		ABar:     g1.One(),
		D:        g1.One(),
		ProofVC1: proofVC1,
		ProofVC2: proofVC2,
	}

	bytes, err := pok.ToBytesCompressedForm()

	assert.NoError(t, err, "error when encoding PoKOfSignatureProof to compressed form")
	expectedLength := 380
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

func TestPubKeySerializeDeserialize(t *testing.T) {
	// Step 1: Create a testing key pair with 5 generators
	kpTest := zkptest.CreateTestingKP(t, 5)

	// Extract the public key
	pubKey := kpTest.PublicKey

	// Step 2: Serialize the public key
	serializedPk := pubKey.Serialize()
	assert.NotNil(t, serializedPk, "serialized public key should not be nil")
	assert.Greater(t, len(serializedPk), 0, "serialized public key should not be empty")

	// Step 3: Deserialize the serialized bytes back into a PublicKey
	deserializedPubKey, err := fhks_bbs_plus.DeserializePublicKey(serializedPk)
	assert.NoError(t, err, "deserialization of public key should not return an error")
	assert.NotNil(t, deserializedPubKey, "deserialized public key should not be nil")

	// Step 4: Verify that the deserialized public key matches the original

	// Test W component
	g2 := bls12381.NewG2()
	diffG2Point := &bls12381.PointG2{}
	g2.Sub(diffG2Point, deserializedPubKey.W, pubKey.W)
	assert.True(t, g2.IsZero(diffG2Point), "W component of the public key does not match")

	// Test H0 component
	g1 := bls12381.NewG1()
	diffG1PointH0 := &bls12381.PointG1{}
	g1.Sub(diffG1PointH0, deserializedPubKey.H0, pubKey.H0)
	assert.True(t, g1.IsZero(diffG1PointH0), "H0 component of the public key does not match")

	// Test H components
	assert.Equal(t, len(pubKey.H), len(deserializedPubKey.H), "length of H components does not match")
	for i := range pubKey.H {
		diffG1PointH := &bls12381.PointG1{}
		g1.Sub(diffG1PointH, deserializedPubKey.H[i], pubKey.H[i])
		assert.True(t, g1.IsZero(diffG1PointH), fmt.Sprintf("H[%d] component of the public key does not match", i))
	}
}

func TestThresholdSignatureSerializeDeserialize(t *testing.T) {
	g1 := bls12381.NewG1()

	msgNum := 5
	msgs := test.Messages[:msgNum]

	kp := zkptest.CreateTestingKP(t, msgNum)

	revealed := []int{0, 2}
	proofRqNoNonce := zkptest.CreateProofReqNoNonce(t, kp, msgs, revealed)
	signature := proofRqNoNonce.Signature

	bytes, err := signature.ToBytes()
	assert.NoError(t, err, "serialization should not return an error")
	assert.NotNil(t, bytes, "serialized signature should not be nil")
	assert.Equal(t, len(bytes), 48+32+32, "serialized signature should have correct length")

	// Deserialize the signature
	deserializedSig, err := fhks_bbs_plus.ThresholdSignatureFromBytes(bytes)
	assert.NoError(t, err, "deserialization should not return an error")
	assert.NotNil(t, deserializedSig, "deserialized signature should not be nil")

	diffG1Point := &bls12381.PointG1{}
	g1.Sub(diffG1Point, deserializedSig.CapitalA, signature.CapitalA)
	assert.True(t, g1.IsZero(diffG1Point), "CapitalA component does not match")

	assert.True(t, deserializedSig.E.Equal(signature.E), "E component does not match")
	assert.True(t, deserializedSig.S.Equal(signature.S), "S component does not match")
}
