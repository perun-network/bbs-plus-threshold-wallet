package helper

import (
	"encoding/binary"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
)

// GetRandomElements creates a k-size vector of n-size vectors of random field elements
func GetRandomElements(rng *rand.Rand, k, n int) [][]*bls12381.Fr {
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

// GetRandomMessagesFromSeed creates a k-size vector of n-size vectors of random messages (field elements).
func GetRandomMessagesFromSeed(seedArray [16]uint8, k int, n int) [][]*bls12381.Fr {
	seed := int64(binary.BigEndian.Uint64(seedArray[:]))
	rng := rand.New(rand.NewSource(seed))

	return GetRandomElements(rng, k, n)
}
