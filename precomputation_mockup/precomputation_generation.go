package precomputation_mockup

import (
	"encoding/binary"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
	fhksbbsplus "github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
)

type PCFPCGOutput struct {
	Sk       *bls12381.Fr
	SkShares []*bls12381.Fr
	AShares  [][]*bls12381.Fr
	EShares  [][]*bls12381.Fr
	SShares  [][]*bls12381.Fr
	AeTerms  [][][][2]*bls12381.Fr
	AsTerms  [][][][2]*bls12381.Fr
	AskTerms [][][][2]*bls12381.Fr
}

func GeneratePPPrecomputation(seedArray [16]uint8, t, n, k int) (*bls12381.Fr, []*fhksbbsplus.PerPartyPrecomputations) {
	output := GeneratePCFPCGOutput(seedArray, t, n, k)
	return output.Sk, CreatePPPrecomputationFromALLVOLEEvaluation(k, n,
		output.SkShares,
		output.AShares,
		output.EShares,
		output.SShares,
		output.AeTerms,
		output.AsTerms,
		output.AskTerms,
	)

}

func GeneratePCFPCGOutput(seedArray [16]uint8, t int, n int, k int) PCFPCGOutput {
	seed := int64(binary.BigEndian.Uint64(seedArray[:]))
	rng := rand.New(rand.NewSource(seed))
	sk, skShares := helper.GetShamirSharedRandomElement(rng, t, n)
	aShares := helper.GetRandomElements(rng, n, k)
	eShares := helper.GetRandomElements(rng, n, k)
	sShares := helper.GetRandomElements(rng, n, k)
	aeTerms := helper.MakeAllPartiesOLE(rng, n, k, aShares, eShares)
	asTerms := helper.MakeAllPartiesOLE(rng, n, k, aShares, sShares)
	askTerms := helper.MakeAllPartiesVOLE(rng, n, k, aShares, skShares)

	return PCFPCGOutput{sk, skShares, aShares, eShares, sShares, aeTerms, asTerms, askTerms}
}

func CreatePPPrecomputationFromALLVOLEEvaluation(
	k int,
	n int,
	skShares []*bls12381.Fr,
	aShares, eShares, sShares [][]*bls12381.Fr,
	aeTerms, asTerms, askTerms [][][][2]*bls12381.Fr,
) []*fhksbbsplus.PerPartyPrecomputations {
	precomputations := make([]*fhksbbsplus.PerPartyPrecomputations, n)
	for iN := 0; iN < n; iN++ {
		preSignatureList := make([]*fhksbbsplus.PerPartyPreSignature, k)

		for iK := 0; iK < k; iK++ {
			aeTermOwn := bls12381.NewFr().Set(aShares[iK][iN])
			aeTermOwn.Mul(aeTermOwn, eShares[iK][iN])
			asTermOwn := bls12381.NewFr().Set(aShares[iK][iN])
			asTermOwn.Mul(asTermOwn, sShares[iK][iN])
			askTermOwn := bls12381.NewFr().Set(aShares[iK][iN])
			askTermOwn.Mul(askTermOwn, skShares[iN])

			aeTermsA := make([]*bls12381.Fr, n)
			aeTermsE := make([]*bls12381.Fr, n)
			asTermsA := make([]*bls12381.Fr, n)
			asTermsS := make([]*bls12381.Fr, n)
			askTermsA := make([]*bls12381.Fr, n)
			askTermsSK := make([]*bls12381.Fr, n)

			for jN := 0; jN < n; jN++ {
				aeTermsA[jN] = bls12381.NewFr()
				aeTermsA[jN].Set(aeTerms[iK][iN][jN][0])
				aeTermsE[jN] = bls12381.NewFr()
				aeTermsE[jN].Set(aeTerms[iK][jN][iN][1])
				asTermsA[jN] = bls12381.NewFr()
				asTermsA[jN].Set(asTerms[iK][iN][jN][0])
				asTermsS[jN] = bls12381.NewFr()
				asTermsS[jN].Set(asTerms[iK][jN][iN][1])
				askTermsA[jN] = bls12381.NewFr()
				askTermsA[jN].Set(askTerms[iK][iN][jN][0])
				askTermsSK[jN] = bls12381.NewFr()
				askTermsSK[jN].Set(askTerms[iK][jN][iN][1])
			}

			preSignatureList[iK] = &fhksbbsplus.PerPartyPreSignature{
				AShare:     aShares[iK][iN],
				EShare:     eShares[iK][iN],
				SShare:     sShares[iK][iN],
				AeTermOwn:  aeTermOwn,
				AsTermOwn:  asTermOwn,
				AskTermOwn: askTermOwn,
				AeTermsA:   aeTermsA,
				AeTermsE:   aeTermsE,
				AsTermsA:   asTermsA,
				AsTermsS:   asTermsS,
				AskTermsA:  askTermsA,
				AskTermsSK: askTermsSK,
			}
		}

		precomputations[iN] = &fhksbbsplus.PerPartyPrecomputations{
			Index:         iN,
			SkShare:       skShares[iN],
			PreSignatures: preSignatureList,
		}
	}

	return precomputations
}
