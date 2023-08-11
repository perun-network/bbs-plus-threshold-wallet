package helper

import (
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
)

// Gets twice t elements of each party and creates the following ole correlation:
// It holds that res[i_s][i_x][i_y][0] + res[i_s][i_x][i_y][1] = x[i_s][i_x] * y[i_s][i_y] (for each i_s in k, i_x in n, i_y in n)
// Party i is supposed to own all res[i_s][i][j][0] and res[i_s][j][i][1] for all j in [n]#
func MakeAllPartiesOLE(rng *rand.Rand, n, k int, x, y [][]*bls12381.Fr) [][][][2]*bls12381.Fr {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}

	if k != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != k")
	}

	voleCorrelation := make([][][][2]*bls12381.Fr, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("make_all_parties_vole got ill-structured input format x[i_k].len() != n")
		}
		if n != len(y[i]) {
			panic("make_all_parties_vole got ill-structured input format y[i].len() != n")
		}
		voleCorrelation[i] = make([][][2]*bls12381.Fr, n)
		for j := 0; j < n; j++ {
			voleCorrelation[i][j] = make([][2]*bls12381.Fr, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l][0], voleCorrelation[i][j][l][1] = makeOLESingle(rng, x[i][j], y[i][l])
			}
		}
	}
	return voleCorrelation
}

// Gets t elements and one scalar of each party (x[i_k][i]: element i_k of party i, y[i]: scalar of party i)
func MakeAllPartiesVOLE(rng *rand.Rand, n, k int, x [][]*bls12381.Fr, y []*bls12381.Fr) [][][][2]*bls12381.Fr {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}
	if n != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != n")
	}
	voleCorrelation := make([][][][2]*bls12381.Fr, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("make_all_parties_vole got ill-structured input format x[i_k].len() != n")
		}
		voleCorrelation[i] = make([][][2]*bls12381.Fr, n)
		for j := 0; j < n; j++ {
			if n != len(y) {
				panic("make_all_parties_vole got ill-structured input format y[i].len() != n")
			}
			voleCorrelation[i][j] = make([][2]*bls12381.Fr, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l][0], voleCorrelation[i][j][l][1] = makeOLESingle(rng, x[i][j], y[l])
			}
		}
	}
	return voleCorrelation
}

// Function to compute the OLE correlation for a single pair of field elements
// Gets inputs x and y and generates u,v such that x*y = u+ v
func makeOLESingle(rng *rand.Rand, x, y *bls12381.Fr) (*bls12381.Fr, *bls12381.Fr) {
	u := bls12381.NewFr()
	_, err := u.Rand(rng)
	if err != nil {
		panic(err)
	}
	v := bls12381.NewFr().Set(x)
	v.Mul(v, y)
	v.Sub(v, u)
	return u, v
}
