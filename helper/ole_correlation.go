package helper

import (
	crand "crypto/rand"
	bls12381 "github.com/kilic/bls12-381"
	"math/rand"
)

// OLECorrelation represents the correlation for Oblivious Linear Evaluation (OLE).
type OLECorrelation struct {
	U *bls12381.Fr
	V *bls12381.Fr
}

// MakeAllPartiesOLE generates OLE correlations for all parties based on input data.
func MakeAllPartiesOLENoRNG(k, n int, x, y [][]*bls12381.Fr) [][][]*OLECorrelation {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}

	if k != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != k")
	}

	voleCorrelation := make([][][]*OLECorrelation, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("MakeAllPartiesOLE got ill-structured input format x[i_k].len() != n")
		}
		if n != len(y[i]) {
			panic("MakeAllPartiesOLE got ill-structured input format y[i].len() != n")
		}

		voleCorrelation[i] = make([][]*OLECorrelation, n)
		for j := 0; j < n; j++ {
			voleCorrelation[i][j] = make([]*OLECorrelation, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l] = makeOLESingleNoRNG(x[i][j], y[i][l])
			}
		}
	}
	return voleCorrelation
}

// MakeAllPartiesOLE generates OLE correlations for all parties based on input data.
func MakeAllPartiesOLE(rng *rand.Rand, k, n int, x, y [][]*bls12381.Fr) [][][]*OLECorrelation {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}

	if k != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != k")
	}

	voleCorrelation := make([][][]*OLECorrelation, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("MakeAllPartiesOLE got ill-structured input format x[i_k].len() != n")
		}
		if n != len(y[i]) {
			panic("MakeAllPartiesOLE got ill-structured input format y[i].len() != n")
		}

		voleCorrelation[i] = make([][]*OLECorrelation, n)
		for j := 0; j < n; j++ {
			voleCorrelation[i][j] = make([]*OLECorrelation, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l] = makeOLESingle(rng, x[i][j], y[i][l])
			}
		}
	}
	return voleCorrelation
}

// MakeAllPartiesVOLE Gets t elements and one scalar of each party (x[i_k][i]: element i_k of party i, y[i]: scalar of party i)
func MakeAllPartiesVOLE(rng *rand.Rand, k, n int, x [][]*bls12381.Fr, y []*bls12381.Fr) [][][]*OLECorrelation {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}
	if n != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != n")
	}
	voleCorrelation := make([][][]*OLECorrelation, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("make_all_parties_vole got ill-structured input format x[i_k].len() != n")
		}
		voleCorrelation[i] = make([][]*OLECorrelation, n)
		for j := 0; j < n; j++ {
			if n != len(y) {
				panic("make_all_parties_vole got ill-structured input format y[i].len() != n")
			}
			voleCorrelation[i][j] = make([]*OLECorrelation, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l] = makeOLESingle(rng, x[i][j], y[l])
			}
		}
	}
	return voleCorrelation
}

func MakeAllPartiesVOLENoRNG(k, n int, x [][]*bls12381.Fr, y []*bls12381.Fr) [][][]*OLECorrelation {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}
	if n != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != n")
	}
	voleCorrelation := make([][][]*OLECorrelation, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("make_all_parties_vole got ill-structured input format x[i_k].len() != n")
		}
		voleCorrelation[i] = make([][]*OLECorrelation, n)
		for j := 0; j < n; j++ {
			if n != len(y) {
				panic("make_all_parties_vole got ill-structured input format y[i].len() != n")
			}
			voleCorrelation[i][j] = make([]*OLECorrelation, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l] = makeOLESingleNoRNG(x[i][j], y[l])
			}
		}
	}
	return voleCorrelation
}

// makeOLESingle computes the OLE correlation for a single pair of field elements.
// For inputs x and y, it generates u,v such that x*y = u+v.
func makeOLESingle(rng *rand.Rand, x, y *bls12381.Fr) *OLECorrelation {
	u := bls12381.NewFr()
	_, err := u.Rand(rng)
	if err != nil {
		panic(err)
	}
	v := bls12381.NewFr().Set(x)
	v.Mul(v, y)
	v.Sub(v, u)
	return &OLECorrelation{u, v}
}

func makeOLESingleNoRNG(x, y *bls12381.Fr) *OLECorrelation {
	u := bls12381.NewFr()
	_, err := u.Rand(crand.Reader)
	if err != nil {
		panic(err)
	}
	v := bls12381.NewFr().Set(x)
	v.Mul(v, y)
	v.Sub(v, u)
	return &OLECorrelation{u, v}
}
