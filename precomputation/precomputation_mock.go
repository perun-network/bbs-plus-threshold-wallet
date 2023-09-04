package precomputation

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
	AeTerms  [][][]*helper.OLECorrelation
	AsTerms  [][][]*helper.OLECorrelation
	AskTerms [][][]*helper.OLECorrelation
}

func GeneratePPPrecomputation(seedArray [16]uint8, t, k, n int) (*bls12381.Fr, []*fhksbbsplus.PerPartyPrecomputations) {
	output := GeneratePCFPCGOutput(seedArray, t, k, n)
	return output.Sk, CreatePPPrecomputationFromVOLEEvaluation(k, n,
		output.SkShares,
		output.AShares,
		output.EShares,
		output.SShares,
		output.AeTerms,
		output.AsTerms,
		output.AskTerms,
	)

}

func GeneratePCFPCGOutput(seedArray [16]uint8, t int, k int, n int) PCFPCGOutput {
	seed := int64(binary.BigEndian.Uint64(seedArray[:]))
	rng := rand.New(rand.NewSource(seed))
	sk, skShares := helper.GetShamirSharedRandomElement(rng, t, n)
	aShares := helper.GetRandomElements(rng, k, n)
	eShares := helper.GetRandomElements(rng, k, n)
	sShares := helper.GetRandomElements(rng, k, n)
	aeTerms := helper.MakeAllPartiesOLE(rng, k, n, aShares, eShares)
	asTerms := helper.MakeAllPartiesOLE(rng, k, n, aShares, sShares)
	askTerms := helper.MakeAllPartiesVOLE(rng, k, n, aShares, skShares)

	return PCFPCGOutput{sk, skShares, aShares, eShares, sShares, aeTerms, asTerms, askTerms}
}

func CreatePPPrecomputationFromVOLEEvaluation(
	k int,
	n int,
	skShares []*bls12381.Fr,
	aShares, eShares, sShares [][]*bls12381.Fr,
	aeTerms, asTerms, askTerms [][][]*helper.OLECorrelation,
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
				aeTermsA[jN].Set(aeTerms[iK][iN][jN].U)
				aeTermsE[jN] = bls12381.NewFr()
				aeTermsE[jN].Set(aeTerms[iK][jN][iN].V)
				asTermsA[jN] = bls12381.NewFr()
				asTermsA[jN].Set(asTerms[iK][iN][jN].U)
				asTermsS[jN] = bls12381.NewFr()
				asTermsS[jN].Set(asTerms[iK][jN][iN].V)
				askTermsA[jN] = bls12381.NewFr()
				askTermsA[jN].Set(askTerms[iK][iN][jN].U)
				askTermsSK[jN] = bls12381.NewFr()
				askTermsSK[jN].Set(askTerms[iK][jN][iN].V)
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
