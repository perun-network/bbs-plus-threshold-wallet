package fhks_bbs_plus_test

import (
	"crypto/rand"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPartialThreshSignDeSerialize(t *testing.T) {
	g1 := bls12381.NewG1()
	capitalAShare := g1.One()
	deltaShare := fhks_bbs_plus.GenerateRandomFr()
	eShare := fhks_bbs_plus.GenerateRandomFr()
	sShare := fhks_bbs_plus.GenerateRandomFr()

	originalPTS := &fhks_bbs_plus.PartialThresholdSignature{
		CapitalAShare: capitalAShare,
		DeltaShare:    deltaShare,
		EShare:        eShare,
		SShare:        sShare,
	}

	bytes, err := originalPTS.ToBytes()
	assert.NoError(t, err)

	deserializedPTS, err := fhks_bbs_plus.PartThreshSigFromBytes(bytes)
	assert.NoError(t, err)

	assert.True(t, g1.Equal(originalPTS.CapitalAShare, deserializedPTS.CapitalAShare), "CapitalAShare mismatch")
	assert.True(t, originalPTS.DeltaShare.Equal(deserializedPTS.DeltaShare), "DeltaShare mismatch")
	assert.True(t, originalPTS.EShare.Equal(deserializedPTS.EShare), "EShare mismatch")
	assert.True(t, originalPTS.SShare.Equal(deserializedPTS.SShare), "SShare mismatch")
}

func TestPartySecretKeySerializationDeserialization(t *testing.T) {
	g2 := bls12381.NewG2()

	skShare := fhks_bbs_plus.GenerateRandomFr()
	publicKey := g2.One()
	index := 17

	originalPSK := &fhks_bbs_plus.PartySecretKey{
		SKeyShare: fhks_bbs_plus.SecretKey{skShare},
		PublicKey: publicKey,
		Index:     index,
	}

	// Serialize the PartySecretKey to bytes
	bytes, err := originalPSK.Marshal()
	assert.NoError(t, err)

	// Deserialize the bytes back to a PartySecretKey
	unmarshalledPSK, err := fhks_bbs_plus.UnmarshalPartyPrivateKey(bytes)
	assert.NoError(t, err)

	// Verify that the original and deserialized keys are equivalent
	assert.True(t, skShare.Equal(unmarshalledPSK.SKeyShare.Fr), "SKShare mismatch")
	assert.True(t, g2.Equal(originalPSK.PublicKey, unmarshalledPSK.PublicKey), "PublicKey mismatch")
	assert.Equal(t, originalPSK.Index, unmarshalledPSK.Index, "Index mismatch")
}

func TestPerPartyPreSignatureSerializationDeserialization(t *testing.T) {
	preSigOriginal, err := randomPreSignature()
	assert.NoError(t, err)

	dataSerialized, err := preSigOriginal.ToBytes()
	assert.NoError(t, err)

	preSigDeserialized, asshare, err := fhks_bbs_plus.FromBytes(dataSerialized)
	assert.NoError(t, err)

	fmt.Println("preSigOriginal.AShare: ", preSigOriginal.AShare)
	fmt.Println("preSigDeserialized.AShare: ", preSigDeserialized.AShare)
	fmt.Println("preSigDeserialized asshare: ", asshare)

	assert.True(t,
		preSigOriginal.AShare.Equal(preSigDeserialized.AShare), "AShare mismatch")
	assert.True(t,
		preSigOriginal.EShare.Equal(preSigDeserialized.EShare), "EShare mismatch")
	assert.True(t,
		preSigOriginal.SShare.Equal(preSigDeserialized.SShare), "SShare mismatch")
	assert.True(t,
		preSigOriginal.AeTermOwn.Equal(preSigDeserialized.AeTermOwn), "AeTermOwn mismatch")
	assert.True(t,
		preSigOriginal.AsTermOwn.Equal(preSigDeserialized.AsTermOwn), "AsTermOwn mismatch")
	assert.True(t,
		preSigOriginal.AskTermOwn.Equal(preSigDeserialized.AskTermOwn), "AskTermOwn mismatch")

	for i := range preSigOriginal.AeTermsA {
		assert.True(t,
			preSigOriginal.AeTermsA[i].Equal(preSigDeserialized.AeTermsA[i]),
			fmt.Sprintf("Ae Terms A mismatch at index %d", i))
	}
	for i := range preSigOriginal.AeTermsE {
		assert.True(t,
			preSigOriginal.AeTermsE[i].Equal(preSigDeserialized.AeTermsE[i]),
			fmt.Sprintf("Ae Terms E mismatch at index %d", i))
	}
	for i := range preSigOriginal.AsTermsA {
		assert.True(t,
			preSigOriginal.AsTermsA[i].Equal(preSigDeserialized.AsTermsA[i]),
			fmt.Sprintf("As Terms A mismatch at index %d", i))
	}
	for i := range preSigOriginal.AsTermsS {
		assert.True(t,
			preSigOriginal.AsTermsS[i].Equal(preSigDeserialized.AsTermsS[i]),
			fmt.Sprintf("As Terms S mismatch at index %d", i))
	}
	for i := range preSigOriginal.AskTermsA {
		assert.True(t,
			preSigOriginal.AskTermsA[i].Equal(preSigDeserialized.AskTermsA[i]),
			fmt.Sprintf("Ask Terms A mismatch at index %d", i))
	}
	for i := range preSigOriginal.AskTermsSK {
		assert.True(t,
			preSigOriginal.AskTermsSK[i].Equal(preSigDeserialized.AskTermsSK[i]),
			fmt.Sprintf("Ask Terms SK mismatch at index %d", i))
	}
}

func TestSerializeDeserializeAeTermsA(t *testing.T) {
	randomFrSlice := func(size int) []*bls12381.Fr {
		slice := make([]*bls12381.Fr, size)
		for i := 0; i < size; i++ {
			elem := bls12381.NewFr()
			_, err := elem.Rand(rand.Reader)
			assert.NoError(t, err)
			slice[i] = elem
		}
		return slice
	}

	// Create a random slice of Fr elements
	originalSlice := randomFrSlice(3)

	// Serialize the slice
	data, err := fhks_bbs_plus.SerializeAeTermsA(originalSlice)
	assert.NoError(t, err)

	// Deserialize the data back into a slice
	deserializedSlice, err := fhks_bbs_plus.DeserializeAeTermsA(data)
	assert.NoError(t, err)

	// Check that the original and deserialized slices are equal
	assert.Equal(t, len(originalSlice), len(deserializedSlice), "Length mismatch")
	for i := range originalSlice {
		assert.True(t,
			originalSlice[i].Equal(deserializedSlice[i]),
			fmt.Sprintf("Element mismatch at index %d", i),
		)
	}
}

func randomPreSignature() (*fhks_bbs_plus.PerPartyPreSignature, error) {
	generateRandomFr := func() (*bls12381.Fr, error) {
		fr := bls12381.NewFr()
		_, err := fr.Rand(rand.Reader)
		if err != nil {
			return nil, err
		}
		return fr, nil
	}

	randomFrSlice := func(size int) ([]*bls12381.Fr, error) {
		slice := make([]*bls12381.Fr, size)
		for i := 0; i < size; i++ {
			elem, err := generateRandomFr()
			if err != nil {
				return nil, err
			}
			slice[i] = elem
		}
		return slice, nil
	}

	aShare, err := generateRandomFr()
	if err != nil {
		return nil, err
	}
	eShare, err := generateRandomFr()
	if err != nil {
		return nil, err
	}
	sShare, err := generateRandomFr()
	if err != nil {
		return nil, err
	}
	aeTermOwn, err := generateRandomFr()
	if err != nil {
		return nil, err
	}
	asTermOwn, err := generateRandomFr()
	if err != nil {
		return nil, err
	}
	askTermOwn, err := generateRandomFr()
	if err != nil {
		return nil, err
	}

	aeTermsA, err := randomFrSlice(3)
	if err != nil {
		return nil, err
	}
	aeTermsE, err := randomFrSlice(3)
	if err != nil {
		return nil, err
	}
	asTermsA, err := randomFrSlice(3)
	if err != nil {
		return nil, err
	}
	asTermsS, err := randomFrSlice(3)
	if err != nil {
		return nil, err
	}
	askTermsA, err := randomFrSlice(3)
	if err != nil {
		return nil, err
	}
	askTermsSK, err := randomFrSlice(3)
	if err != nil {
		return nil, err
	}

	return &fhks_bbs_plus.PerPartyPreSignature{
		AShare:     aShare,
		EShare:     eShare,
		SShare:     sShare,
		AeTermOwn:  aeTermOwn,
		AsTermOwn:  asTermOwn,
		AskTermOwn: askTermOwn,
		AeTermsA:   aeTermsA,
		AeTermsE:   aeTermsE,
		AsTermsA:   asTermsA,
		AsTermsS:   asTermsS,
		AskTermsA:  askTermsA,
		AskTermsSK: askTermsSK,
	}, nil
}
