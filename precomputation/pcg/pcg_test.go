package pcg

import (
	"fmt"
	"math/big"
	"testing"

	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestPCGCombinedEnd2End(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 2, 2, 4) // Small lpn parameters for testing.
	assert.Nil(t, err)

	seeds, err := pcg.TrustedSeedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(false)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	eval0, err := pcg.EvalCombined(seeds[0], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)

	eval1, err := pcg.EvalCombined(seeds[1], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval1)

	keyNr := 9
	root := ring.Roots[keyNr]

	tuple0 := eval0.GenBBSPlusTuple(root)
	tuple1 := eval1.GenBBSPlusTuple(root)

	sk := bls12381.NewFr()
	sk.Add(tuple0.SkShare, tuple1.SkShare)

	seedSk := bls12381.NewFr()
	seedSk.Add(seeds[0].ski, seeds[1].ski)
	assert.Equal(t, 0, sk.Cmp(seedSk))

	a := bls12381.NewFr() // Sum up a0 and a1
	a.Add(tuple0.AShare, tuple1.AShare)

	s := bls12381.NewFr() // Sum up s0 and s1
	s.Add(tuple0.SShare, tuple1.SShare)

	e := bls12381.NewFr() // Sum up e0 and e1
	e.Add(tuple0.EShare, tuple1.EShare)

	alpha := bls12381.NewFr()
	alpha.Add(tuple0.AlphaShare, tuple1.AlphaShare)

	delta := bls12381.NewFr()
	delta.Add(tuple0.DeltaShare, tuple1.DeltaShare)

	ask := bls12381.NewFr() // = delta0
	ask.Mul(a, sk)

	ae := bls12381.NewFr() // = delta1
	ae.Mul(a, e)

	// Check if correlations hold
	askPae := bls12381.NewFr() // = a(sk + e)
	askPae.Add(ask, ae)
	assert.Equal(t, 0, delta.Cmp(askPae))

	as := bls12381.NewFr()
	as.Mul(a, s)
	assert.Equal(t, 0, alpha.Cmp(as))
}

func TestPCGCombinedEnd2EndTau3N3(t *testing.T) {
	pcg, err := NewPCG(128, 10, 3, 3, 2, 4) // Small lpn parameters for testing.
	assert.Nil(t, err)

	seeds, err := pcg.TrustedSeedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(false)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	eval0, err := pcg.EvalCombined(seeds[0], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)

	eval1, err := pcg.EvalCombined(seeds[1], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval1)

	eval2, err := pcg.EvalCombined(seeds[2], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval2)

	keyNr := 9
	root := ring.Roots[keyNr]

	tuple0 := eval0.GenBBSPlusTuple(root)
	tuple1 := eval1.GenBBSPlusTuple(root)
	tuple2 := eval2.GenBBSPlusTuple(root)

	sk := bls12381.NewFr().Zero()
	sk.Add(tuple0.SkShare, tuple1.SkShare)
	sk.Add(sk, tuple2.SkShare)

	fmt.Printf("sk: %v\n", sk)

	seedSk := bls12381.NewFr().Zero()
	seedSk.Add(seeds[0].ski, seeds[1].ski)
	seedSk.Add(seedSk, seeds[2].ski)
	assert.Equal(t, 0, sk.Cmp(seedSk))

	a := bls12381.NewFr().Zero() // Sum up a0 and a1
	a.Add(tuple0.AShare, tuple1.AShare)
	a.Add(a, tuple2.AShare)

	s := bls12381.NewFr().Zero() // Sum up s0 and s1
	s.Add(tuple0.SShare, tuple1.SShare)
	s.Add(s, tuple2.SShare)

	e := bls12381.NewFr().Zero() // Sum up e0 and e1
	e.Add(tuple0.EShare, tuple1.EShare)
	e.Add(e, tuple2.EShare)

	alpha := bls12381.NewFr().Zero()
	alpha.Add(tuple0.AlphaShare, tuple1.AlphaShare)
	alpha.Add(alpha, tuple2.AlphaShare)

	delta := bls12381.NewFr().Zero()
	delta.Add(tuple0.DeltaShare, tuple1.DeltaShare)
	delta.Add(delta, tuple2.DeltaShare)

	ask := bls12381.NewFr().Zero() // = delta0
	ask.Mul(a, sk)

	ae := bls12381.NewFr().Zero() // = delta1
	ae.Mul(a, e)

	delta1 := bls12381.NewFr().Zero()
	delta1.Add(tuple0.DeltaShare1, tuple1.DeltaShare1)
	delta1.Add(delta1, tuple2.DeltaShare1)

	delta2 := bls12381.NewFr().Zero()
	delta2.Add(tuple0.DeltaShare2, tuple1.DeltaShare2)
	delta2.Add(delta2, tuple2.DeltaShare2)

	deltaX := bls12381.NewFr().Zero()
	deltaX.Add(delta1, delta2)
	fmt.Println("delta == deltaX:", delta.Cmp(deltaX) == 0)
	fmt.Println("delta1 == ae:", delta1.Cmp(ae) == 0)
	fmt.Println("delta0 == ask:", delta2.Cmp(ask) == 0)

	// Check if correlations hold
	as := bls12381.NewFr().Zero()
	as.Mul(a, s)
	assert.Equal(t, 0, alpha.Cmp(as))

	askPae := bls12381.NewFr().Zero() // = a(sk + e)
	askPae.Add(ask, ae)
	assert.Equal(t, 0, delta.Cmp(askPae))

}

func TestRootsOfUnity(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 2, 2, 4) // Small lpn parameters for testing.
	assert.Nil(t, err)

	ring, err := pcg.GetRing(false)
	assert.Nil(t, err)

	twoPowN := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(pcg.N)), nil)

	assert.Equal(t, 0, twoPowN.Cmp(big.NewInt(int64(len(ring.Roots)))))

	// roots must be unique
	for i := 0; i < len(ring.Roots); i++ {
		for j := 0; j < len(ring.Roots); j++ {
			if i != j {
				assert.False(t, ring.Roots[i].Equal(ring.Roots[j]))
			}
		}
	}

	// for each ring.root evaluate ring.div
	zero := big.NewInt(0)
	for i := 0; i < len(ring.Roots); i++ {
		assert.Equal(t, 0, zero.Cmp(ring.Div.Evaluate(ring.Roots[i]).ToBig()))
	}
}

func BenchmarkRootOfUnityGen15(b *testing.B) {
	benchmarkRootOfUnityGen(b, 15)
}
func BenchmarkRootOfUnityGen16(b *testing.B) {
	benchmarkRootOfUnityGen(b, 16)
}
func BenchmarkRootOfUnityGen17(b *testing.B) {
	benchmarkRootOfUnityGen(b, 17)
}
func BenchmarkRootOfUnityGen18(b *testing.B) {
	benchmarkRootOfUnityGen(b, 18)
}
func BenchmarkRootOfUnityGen19(b *testing.B) {
	benchmarkRootOfUnityGen(b, 19)
}
func BenchmarkRootOfUnityGen20(b *testing.B) {
	benchmarkRootOfUnityGen(b, 20)
}

func BenchmarkRootOfUnityGenFast15(b *testing.B) {
	benchmarkRootOfUnityGenFast(b, 15)
}
func BenchmarkRootOfUnityGenFast16(b *testing.B) {
	benchmarkRootOfUnityGenFast(b, 16)
}
func BenchmarkRootOfUnityGenFast17(b *testing.B) {
	benchmarkRootOfUnityGenFast(b, 17)
}
func BenchmarkRootOfUnityGenFast18(b *testing.B) {
	benchmarkRootOfUnityGenFast(b, 18)
}
func BenchmarkRootOfUnityGenFast19(b *testing.B) {
	benchmarkRootOfUnityGenFast(b, 19)
}
func BenchmarkRootOfUnityGenFast20(b *testing.B) {
	benchmarkRootOfUnityGenFast(b, 20)
}

func benchmarkRootOfUnityGen(b *testing.B, N int) {
	pcg, _ := NewPCG(128, N, 2, 2, 2, 4)

	for i := 0; i < b.N; i++ {
		_, _ = pcg.GetRing(false)
	}
}

func benchmarkRootOfUnityGenFast(b *testing.B, N int) {
	pcg, _ := NewPCG(128, N, 2, 2, 2, 4)

	for i := 0; i < b.N; i++ {
		_, _ = pcg.GetRing(true)
	}
}
