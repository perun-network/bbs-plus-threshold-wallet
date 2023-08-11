package fhks_bbs_plus

import (
	"encoding/binary"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
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
