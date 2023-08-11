package test

import (
	"testing"

	bls12381 "github.com/kilic/bls12-381"
	fhksbbsplus "github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation_mockup"
)

var (
	seedPre = [16]uint8{
		0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
		0xe5}
	threshold = 3 // Security threshold (t-out-of-n)
	n         = 6 // Number of servers
	k         = 3 // Presignature to create
	indices   = [][]int{{1, 3, 5}, {1, 5, 2}, {2, 4, 5}}
)

func TestAllPrecomputationGeneration(t *testing.T) {
	output := precomputation_mockup.GeneratePCFPCGOutput(seedPre, threshold, n, k)

	sk := output.Sk
	skShares := output.SkShares
	aShares := output.AShares
	eShares := output.EShares
	sShares := output.SShares
	aeTerms := output.AeTerms
	asTerms := output.AsTerms
	askTerms := output.AskTerms

	perPartyPrecomputation := precomputation_mockup.CreatePPPrecomputationFromALLVOLEEvaluation(
		k, n, skShares, aShares, eShares, sShares, aeTerms, asTerms, askTerms)

	testPCFPCGOutputAeAsAsk(t, k, indices, sk, aShares, eShares, sShares, aeTerms, asTerms, askTerms)

	for iK := 0; iK < k; iK++ {
		testInterpolationForSk(t, sk, skShares, indices[iK])
	}

	testPerPartyPrecomputationsWithoutCoefficients(t, k, indices, perPartyPrecomputation,
		sk, aShares, eShares, sShares)
}

func testPCFPCGOutputAeAsAsk(t *testing.T,
	k int,
	indices [][]int,
	sk *bls12381.Fr,
	aShares, eShares, sShares [][]*bls12381.Fr,
	aeTerms, asTerms, askTerms [][][][2]*bls12381.Fr,
) {
	for iK := 0; iK < k; iK++ {
		a := bls12381.NewFr().Zero()
		e := bls12381.NewFr().Zero()
		s := bls12381.NewFr().Zero()
		aeDirect := bls12381.NewFr().One()
		asDirect := bls12381.NewFr().One()
		askDirect := bls12381.NewFr().One()

		aeIndirect := bls12381.NewFr().Zero()
		asIndirect := bls12381.NewFr().Zero()
		askIndirect := bls12381.NewFr().Zero()

		for _, iN := range indices[iK] {
			a.Add(a, aShares[iK][iN-1])
			e.Add(e, eShares[iK][iN-1])
			s.Add(s, sShares[iK][iN-1])
		}

		aeDirect.Mul(aeDirect, a)
		aeDirect.Mul(aeDirect, e)

		asDirect.Mul(asDirect, a)
		asDirect.Mul(asDirect, s)

		askDirect.Mul(askDirect, a)
		askDirect.Mul(askDirect, sk)

		for _, iN := range indices[iK] {
			for _, jN := range indices[iK] {
				tmpAE := bls12381.NewFr().Zero()
				tmpAS := bls12381.NewFr().Zero()
				tmpASK := bls12381.NewFr().Zero()
				tmpAE.Add(tmpAE, aeTerms[iK][iN-1][jN-1][0])
				tmpAE.Add(tmpAE, aeTerms[iK][iN-1][jN-1][1])
				tmpAS.Add(tmpAS, asTerms[iK][iN-1][jN-1][0])
				tmpAS.Add(tmpAS, asTerms[iK][iN-1][jN-1][1])
				tmpASK.Add(tmpASK, askTerms[iK][iN-1][jN-1][0])
				tmpASK.Add(tmpASK, askTerms[iK][iN-1][jN-1][1])

				lagrangeCoeff := helper.Get0LagrangeCoefficientFr(indices[iK], jN)
				tmpASK.Mul(tmpASK, lagrangeCoeff)

				aeIndirect.Add(aeIndirect, tmpAE)
				asIndirect.Add(asIndirect, tmpAS)
				askIndirect.Add(askIndirect, tmpASK)
			}
		}

		if !aeDirect.Equal(aeIndirect) {
			t.Errorf("Computation of AE is not consistent")
		}

		if !asDirect.Equal(asIndirect) {
			t.Errorf("Computation of AS is not consistent")
		}

		if !askDirect.Equal(askIndirect) {
			t.Errorf("Computation of ASK is not consistent")
		}
	}
}

func testInterpolationForSk(t *testing.T, sk *bls12381.Fr, skShares []*bls12381.Fr, indices []int) {
	interpolationResult := bls12381.NewFr()
	for _, i := range indices {
		tmp := bls12381.NewFr().Set(skShares[i-1])
		tmp.Mul(tmp, helper.Get0LagrangeCoefficientFr(indices, i))
		interpolationResult.Add(interpolationResult, tmp)
	}
	if !sk.Equal(interpolationResult) {
		t.Errorf("Problems with interpolation")
	}
}

func testPerPartyPrecomputationsWithoutCoefficients(t *testing.T, k int, indices [][]int,
	precomputations []*fhksbbsplus.PerPartyPrecomputations, sk *bls12381.Fr,
	aShares, eShares, sShares [][]*bls12381.Fr) {

	coefficients := make([][]*bls12381.Fr, len(indices))
	for i, idx := range indices {
		coefficients[i] = helper.Get0LagrangeCoefficientSetFr(idx)
	}

	testPerPartyPrecomputationsWithCoefficients(
		t,
		k,
		indices,
		coefficients,
		precomputations,
		sk, aShares, eShares, sShares)
}

func testPerPartyPrecomputationsWithCoefficients(
	t *testing.T,
	k int,
	indices [][]int,
	coefficients [][]*bls12381.Fr,
	precomputations []*fhksbbsplus.PerPartyPrecomputations,
	sk *bls12381.Fr,
	aShares, eShares, sShares [][]*bls12381.Fr,
) {
	for iK := 0; iK < k; iK++ {
		aDirect := bls12381.NewFr().Zero()
		eDirect := bls12381.NewFr().Zero()
		sDirect := bls12381.NewFr().Zero()
		aIndirect := bls12381.NewFr().Zero()
		eIndirect := bls12381.NewFr().Zero()
		sIndirect := bls12381.NewFr().Zero()

		aeIndirect := bls12381.NewFr().Zero()
		asIndirect := bls12381.NewFr().Zero()
		askIndirect := bls12381.NewFr().Zero()

		for _, elI := range indices[iK] {
			aDirect.Add(aDirect, aShares[iK][elI-1])
			eDirect.Add(eDirect, eShares[iK][elI-1])
			sDirect.Add(sDirect, sShares[iK][elI-1])

			aIndirect.Add(aIndirect, precomputations[elI-1].PreSignatures[iK].AShare)
			eIndirect.Add(eIndirect, precomputations[elI-1].PreSignatures[iK].EShare)
			sIndirect.Add(sIndirect, precomputations[elI-1].PreSignatures[iK].SShare)
		}

		aeDirect := bls12381.NewFr().Set(aDirect)
		aeDirect.Mul(aeDirect, eDirect)
		asDirect := bls12381.NewFr().Set(aDirect)
		asDirect.Mul(asDirect, sDirect)
		askDirect := bls12381.NewFr().Set(aDirect)
		askDirect.Mul(askDirect, sk)

		//Compute share of each party and add it to the total
		for indI, elI := range indices[iK] {
			//For (ae,as)-shares start with the multiplication of both own shares
			shareOfAE := bls12381.NewFr().Set(precomputations[elI-1].PreSignatures[iK].AeTermOwn)
			shareOfAS := bls12381.NewFr().Set(precomputations[elI-1].PreSignatures[iK].AsTermOwn)

			// ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets other-index-lagrange
			shareOfAsk := bls12381.NewFr().Zero()
			tmpAskOwnLagrange := bls12381.NewFr().Set(precomputations[elI-1].PreSignatures[iK].AskTermOwn) // Own-index-lagrange starts with multiplication of both own shares

			for indJ, elJ := range indices[iK] {
				if elJ != elI {
					// Add shares of a_i * e/s_j (ae/sTermsA), a_j * e_i (ae/sTermsA/s)
					shareOfAE.Add(shareOfAE, precomputations[elI-1].PreSignatures[iK].AeTermsA[elJ-1])
					shareOfAE.Add(shareOfAE, precomputations[elI-1].PreSignatures[iK].AeTermsE[elJ-1])
					shareOfAS.Add(shareOfAS, precomputations[elI-1].PreSignatures[iK].AsTermsA[elJ-1])
					shareOfAS.Add(shareOfAS, precomputations[elI-1].PreSignatures[iK].AsTermsS[elJ-1])

					// Share of a_i * sk_j (using j's lagrange coefficient) is added to shareOfAsk
					tmp := bls12381.NewFr().Set(precomputations[elI-1].PreSignatures[iK].AskTermsA[elJ-1])
					tmp.Mul(tmp, coefficients[iK][indJ])
					shareOfAsk.Add(shareOfAsk, tmp)

					//Share of a_j * sk_i (using i's lagrange coefficeint) is added to tmp_ask_own_lagrange (coefficient is applied later for all at once)
					tmpAskOwnLagrange.Add(tmpAskOwnLagrange, precomputations[elI-1].PreSignatures[iK].AskTermsSK[elJ-1])
				}
			}

			//Apply i's lagrange coefficient to sum of share of all cross-terms incoperating sk_i and add result to share of ask
			tmpAskOwnLagrange.Mul(tmpAskOwnLagrange, coefficients[iK][indI])
			shareOfAsk.Add(shareOfAsk, tmpAskOwnLagrange)

			// Add computed share of ae/as/ask to the computation of ae/as/ask
			aeIndirect.Add(aeIndirect, shareOfAE)
			asIndirect.Add(asIndirect, shareOfAS)
			askIndirect.Add(askIndirect, shareOfAsk)
		}

		if !aDirect.Equal(aIndirect) {
			t.Errorf("Computation of A is not consistent")
		}
		if !eDirect.Equal(eIndirect) {
			t.Errorf("Computation of E is not consistent")
		}
		if !sDirect.Equal(sIndirect) {
			t.Errorf("Computation of S is not consistent")
		}
		if !aeDirect.Equal(aeIndirect) {
			t.Errorf("Computation of AE is not consistent")
		}
		if !asDirect.Equal(asIndirect) {
			t.Errorf("Computation of AS is not consistent")
		}
		if !askDirect.Equal(askIndirect) {
			t.Errorf("Computation of ASK is not consistent")
		}
	}

}
