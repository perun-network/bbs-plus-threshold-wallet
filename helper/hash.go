package helper

import (
	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/blake2b"
)

const FR_UNCOMPRESSED_SIZE = 32

func HashToFr(data []byte) *bls12381.Fr {
	// Create a new BLAKE2b hash with the desired output size
	// hasher, err := blake2.New(FR_UNCOMPRESSED_SIZE, nil)
	hasher, err := blake2b.New(FR_UNCOMPRESSED_SIZE, nil)
	if err != nil {
		panic(err)
	}

	// Write data to the hasher
	hasher.Write(data)

	// Get the hash result
	res := hasher.Sum(nil)

	// Convert the hash result to an Fr element
	fr := &bls12381.Fr{}
	fr.FromBytes(res)

	return fr
}
