package fhks_bbs_plus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
)

const (
	G1Size = 96
	G2Size = 192
	FrSize = 32
)

type PublicKey struct {
	H0 *bls12381.PointG1
	H  []*bls12381.PointG1
	W  *bls12381.PointG2
}

func GeneratePublicKey(seedArray [16]uint8, sk *bls12381.Fr, messageCount int) *PublicKey {
	seed := int64(binary.BigEndian.Uint64(seedArray[:]))
	rng := rand.New(rand.NewSource(seed))
	return GeneratePublicKeyFromRng(rng, sk, messageCount)
}

func GeneratePublicKeyFromRng(rng *rand.Rand, sk *bls12381.Fr, messageCount int) *PublicKey {
	g2 := bls12381.NewG2()
	w := g2.One()
	g2.MulScalar(w, w, sk)
	allH := make([]*bls12381.PointG1, messageCount+1)

	for i := 0; i <= messageCount; i++ {
		g1 := bls12381.NewG1()
		tmp := g1.One()
		r, err := bls12381.NewFr().Rand(rng)
		if err != nil {
			panic(err)
		}
		g1.MulScalar(tmp, tmp, r)
		allH[i] = tmp
	}

	return &PublicKey{
		W:  w,
		H0: allH[0],
		H:  allH[1:],
	}
}

func (pk *PublicKey) ToBytes() ([]byte, error) {
	// Serialize H0
	g1 := bls12381.NewG1()
	h0Bytes := g1.ToBytes(pk.H0)

	// Serialize the number of elements in slice H
	hLengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(hLengthBytes, uint32(len(pk.H)))
	serialized := append(hLengthBytes, h0Bytes...)
	// Serialize each element in slice H
	for _, h := range pk.H {
		serialized = append(serialized, g1.ToBytes(h)...)
	}

	// Serialize W
	g2 := bls12381.NewG2()
	wBytes := g2.ToBytes(pk.W)
	serialized = append(serialized, wBytes...)

	return serialized, nil
}

func (pk *PublicKey) FromBytes(data []byte) error {
	g1 := bls12381.NewG1()
	if len(data) < 4 {
		return errors.New("input data is too short to represent the public key")
	}

	// Deserialize H length
	hLength := int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:] // Remove the length bytes from the data

	// Ensure the data has at least the sizes of H0 and W points
	if len(data) < G1Size+G2Size+hLength*G1Size {
		return errors.New("input data is too short to represent the PublicKey")
	}

	// Deserialize H0
	h0Bytes := data[:G1Size]
	data = data[G1Size:]
	h0, err := g1.FromBytes(h0Bytes)
	if err != nil {
		return fmt.Errorf("deserialize h0 from bytes: %w", err)
	}

	// Deserialize H
	hBytes := data[:G1Size*hLength]
	h := make([]*bls12381.PointG1, hLength)
	for i := 0; i < hLength; i++ {
		offset := i * G1Size
		pointBytes := hBytes[offset : offset+G1Size]
		h[i], err = g1.FromBytes(pointBytes)
		if err != nil {
			return fmt.Errorf("deserialize point %d of h: %w", i, err)
		}
	}

	// Deserialize W
	wBytes := data[G1Size*hLength:]
	w, err := bls12381.NewG2().FromBytes(wBytes)
	if err != nil {
		return fmt.Errorf("deserialize w from bytes: %w", err)
	}

	pk.H0 = h0
	pk.H = h
	pk.W = w
	return nil
}
