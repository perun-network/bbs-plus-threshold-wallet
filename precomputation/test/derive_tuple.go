package test

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation/pcg"
	// "github.com/perun-network/bbs-plus-threshold-wallet/precomputation/pcg/poly"
	"math/big"
	"math/rand"
	"testing"
)

func DeriveTuple(t *testing.T, N int) []*pcg.BBSPlusTuple {
	c, tau := 4, 16
	pcgenerator, err := pcg.NewPCG(128, N, 2, 2, c, tau)
	if err != nil {
		t.Fatal(err)
	}

	ring, err := pcgenerator.GetRing(false)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(rand.Int63()))
	sk, _ := bls12381.NewFr().Rand(rng)

	pow2N := big.NewInt(0)
	pow2N.Exp(big.NewInt(2), big.NewInt(int64(N)), nil)

	// Generate random polynomials
	alphaPoly := RandomPoly(pow2N)
	delta1Poly := RandomPoly(pow2N)
	delta0Poly := RandomPoly(pow2N)
	aPoly := RandomPoly(pow2N)
	ePoly := RandomPoly(pow2N)
	sPoly := RandomPoly(pow2N)

	tupleGenerator := pcg.NewBBSPlusTupleGenerator(sk, aPoly, ePoly, sPoly, alphaPoly, delta0Poly, delta1Poly)

	root := ring.Roots[10]

	// Initialize a slice to store tuples
	tupleArray := make([]*pcg.BBSPlusTuple, 0, N)

	for i := 0; i < N; i++ {
		tuple := tupleGenerator.GenBBSPlusTuple(root)
		tupleArray = append(tupleArray, tuple) // Append each tuple to the slice
	}

	return tupleArray // Return the slice of tuples
}
