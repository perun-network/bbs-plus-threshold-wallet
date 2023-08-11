package fhks_bbs_plus

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
)

type PerPartyPreSignature struct {
	AShare     *bls12381.Fr
	EShare     *bls12381.Fr
	SShare     *bls12381.Fr
	AeTermOwn  *bls12381.Fr
	AsTermOwn  *bls12381.Fr
	AskTermOwn *bls12381.Fr
	AeTermsA   []*bls12381.Fr
	AeTermsE   []*bls12381.Fr
	AsTermsA   []*bls12381.Fr
	AsTermsS   []*bls12381.Fr
	AskTermsA  []*bls12381.Fr
	AskTermsSK []*bls12381.Fr
}

type PerPartyPrecomputations struct {
	Index         int
	SkShare       *bls12381.Fr
	PreSignatures []*PerPartyPreSignature
}

type LivePreSignature struct {
	AShare     *bls12381.Fr
	EShare     *bls12381.Fr
	SShare     *bls12381.Fr
	DeltaShare *bls12381.Fr
	AlphaShare *bls12381.Fr
}

func NewLivePreSignature() *LivePreSignature {
	return &LivePreSignature{
		AShare:     bls12381.NewFr().Zero(),
		EShare:     bls12381.NewFr().Zero(),
		SShare:     bls12381.NewFr().Zero(),
		DeltaShare: bls12381.NewFr().Zero(),
		AlphaShare: bls12381.NewFr().Zero(),
	}
}

func (lps *LivePreSignature) FromPreSignature(ownIndex int, indices []int, preSignature *PerPartyPreSignature) *LivePreSignature {
	lagrangeCoefficients := helper.Get0LagrangeCoefficientSetFr(indices)
	return lps.FromPresignatureWithCoefficients(ownIndex, indices, preSignature, lagrangeCoefficients)

}

func (lps *LivePreSignature) FromPresignatureWithCoefficients(
	ownIndex int,
	indices []int,
	preSignature *PerPartyPreSignature,
	lagrangeCoefficients []*bls12381.Fr) *LivePreSignature {

	//For (ae,as = alpha)-shares start with the multiplication of both own shares
	alphaShare := bls12381.NewFr().Set(preSignature.AsTermOwn)
	aeShare := bls12381.NewFr().Set(preSignature.AeTermOwn)

	//ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets other-index-lagrange
	askShare := bls12381.NewFr().Zero()
	tmpAskOwnCoefficient := bls12381.NewFr().Set(preSignature.AskTermOwn)

	indI := 0
	for indJ, elJ := range indices {
		if elJ != ownIndex {
			//Add shares of a_i * e/s_j (ae/s_terms_a), a_j * e_i (ae/s_terms_a/s)
			aeShare.Add(aeShare, preSignature.AeTermsA[elJ-1])
			aeShare.Add(aeShare, preSignature.AeTermsE[elJ-1])
			alphaShare.Add(alphaShare, preSignature.AsTermsA[elJ-1])
			alphaShare.Add(alphaShare, preSignature.AsTermsS[elJ-1])

			//Share of  a_i * sk_j (using j's lagrange coefficient) is added to share_of_ask
			tmp := bls12381.NewFr().Set(preSignature.AskTermsA[elJ-1])
			tmp.Mul(tmp, lagrangeCoefficients[indJ])

			askShare.Add(askShare, tmp)

			//Share of a_j * sk_i (using i's lagrange coefficeint) is added to tmp_ask_own_lagrange (coefficient is applied later for all at once)
			tmpAskOwnCoefficient.Add(tmpAskOwnCoefficient, preSignature.AskTermsSK[elJ-1])
		} else {
			indI = indJ
		}
	}
	//Apply i's lagrange coefficient to sum of share of all cross-terms incoperating sk_i and add result to share of ask
	tmpAskOwnCoefficient.Mul(tmpAskOwnCoefficient, lagrangeCoefficients[indI])
	askShare.Add(askShare, tmpAskOwnCoefficient)

	// Compute delta_share
	deltaShare := bls12381.NewFr().Set(aeShare)
	deltaShare.Add(deltaShare, askShare)

	lps.AShare.Set(preSignature.AShare)
	lps.EShare.Set(preSignature.EShare)
	lps.SShare.Set(preSignature.SShare)
	lps.DeltaShare.Set(deltaShare)
	lps.AlphaShare.Set(alphaShare)
	return lps
}
