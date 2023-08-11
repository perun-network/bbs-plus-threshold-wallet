package helper

import (
	"encoding/binary"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
)

func GetRandomElements(rng *rand.Rand, n, k int) [][]*bls12381.Fr {
	result := make([][]*bls12381.Fr, k)
	for i := 0; i < k; i++ {
		result[i] = make([]*bls12381.Fr, n)
		for j := 0; j < n; j++ {
			fr := bls12381.NewFr()
			_, err := fr.Rand(rng)
			if err != nil {
				panic(err)
			}
			result[i][j] = fr
		}
	}
	return result
}

func GetRandomMessagesFromSeed(seedArray [16]uint8, c1 int, c2 int) [][]*bls12381.Fr {
	seed := int64(binary.BigEndian.Uint64(seedArray[:]))
	rng := rand.New(rand.NewSource(seed))

	return GetRandomElements(rng, c1, c2)
}
