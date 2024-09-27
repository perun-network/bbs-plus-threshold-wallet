package test

import (
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	// "pcg-bbs-plus/pcg"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation/pcg/poly"
	// "testing"
)

// in this package we initialize the test setup

func RandomPoly(n *big.Int) *poly.Polynomial {
	slice := make([]*bls12381.Fr, n.Int64())

	rng := rand.New(rand.NewSource(rand.Int63()))
	for i := range slice {
		randVal := bls12381.NewFr()
		slice[i] = bls12381.NewFr()
		fr, _ := randVal.Rand(rng)
		slice[i].Set(fr)
	}
	return poly.NewFromFr(slice)
}
