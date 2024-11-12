package precomputation

import (
	"encoding/binary"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"

	fhksbbsplus "github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation/pcg"
	"github.com/perun-network/bbs-plus-threshold-wallet/test"
)

var (
	seedPresignatures = [16]uint8{
		0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
		0xe5}
	seedMessages = [16]uint8{
		0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
		0xe5}
	seedKeys = [16]uint8{
		0x59, 0x62, 0xaa, 0x5d, 0x76, 0xaa, 0xbb, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0xcc, 0xac,
		0xe5}
	messageCount = 5
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

type TupleOutput struct {
	Sk       *bls12381.Fr
	SkShares []*bls12381.Fr
	AShares  [][]*bls12381.Fr
	EShares  [][]*bls12381.Fr
	SShares  [][]*bls12381.Fr
	Alpha    []*bls12381.Fr
	Delta    []*bls12381.Fr
}

func GeneratePPPrecomputationMock(seedArray [16]uint8, t, k, n int) (*bls12381.Fr, []*fhksbbsplus.PerPartyPrecomputations) {
	output := GeneratePCFPCGOutputMocked(seedArray, t, k, n)
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

func GeneratePPPrecomputationTauOutOfN(seedArray [16]uint8, tau, K, N int) (*bls12381.Fr, []*pcg.Seed, [][]*fhksbbsplus.LivePreSignatureSk) {
	signerSet := test.IndicesSignersTestTauOutOfN

	var sk *bls12381.Fr
	livePreSignatures := make([][]*fhksbbsplus.LivePreSignatureSk, K)

	sk, skSeeds, output := GeneratePCFPCGOutputTauOutOfN(seedArray, tau, K, N, signerSet)

	for j := 0; j < K; j++ {
		livePreSignaturesPerMsg := make([]*fhksbbsplus.LivePreSignatureSk, tau)
		for i := 0; i < tau; i++ {
			livePreSignaturesPerMsg[i] = &fhksbbsplus.LivePreSignatureSk{
				SkShare:    output[j][i].SkShare,
				AShare:     output[j][i].AShare,
				EShare:     output[j][i].EShare,
				SShare:     output[j][i].SShare,
				DeltaShare: output[j][i].DeltaShare,
				AlphaShare: output[j][i].AlphaShare,
			}
		}
		livePreSignatures[j] = livePreSignaturesPerMsg
	}

	return sk, skSeeds, livePreSignatures
}

func GeneratePPPrecomputationNOutOfN(seedArray [16]uint8, tau, K, n int) (*bls12381.Fr, []*pcg.Seed, [][]*fhksbbsplus.LivePreSignatureSk) {
	livePreSignatures := make([][]*fhksbbsplus.LivePreSignatureSk, K)

	if tau != n {
		panic("threshold must be n")
	}
	secretKey, skSeeds, output := GeneratePCFPCGOutputNOutOfN(seedArray, tau, K, n)

	for j := 0; j < K; j++ {
		livePreSignaturesPerMsg := make([]*fhksbbsplus.LivePreSignatureSk, tau)
		for i := 0; i < tau; i++ {
			livePreSignaturesPerMsg[i] = &fhksbbsplus.LivePreSignatureSk{
				SkShare:    output[j][i].SkShare,
				AShare:     output[j][i].AShare,
				EShare:     output[j][i].EShare,
				SShare:     output[j][i].SShare,
				DeltaShare: output[j][i].DeltaShare,
				AlphaShare: output[j][i].AlphaShare,
			}
		}
		livePreSignatures[j] = livePreSignaturesPerMsg
	}

	return secretKey, skSeeds, livePreSignatures
}

func GeneratePCFPCGOutputMocked(seedArray [16]uint8, t int, k int, n int) PCFPCGOutput {
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

func GeneratePCFPCGOutputTauOutOfN(seedArray [16]uint8, tau int, k int, N int, signerSet []int) (*bls12381.Fr, []*pcg.Seed, [][]*pcg.BBSPlusTuple) {
	c, t := 2, 4

	pcgenerator, err := pcg.NewPCG(128, 10, N, tau, c, t)
	if err != nil {
		panic(err)
	}

	ring, err := pcgenerator.GetRing(false)
	if err != nil {
		panic(err)
	}
	sk, seeds, err := pcgenerator.SeedGenWithSk()
	if err != nil {
		panic(err)
	}
	randPolys, err := pcgenerator.PickRandomPolynomials()
	if err != nil {
		panic(err)
	}

	root := ring.Roots[10]

	tupleArray := make([][]*pcg.BBSPlusTuple, k)

	for j := 0; j < k; j++ {
		tupleArray[j] = make([]*pcg.BBSPlusTuple, tau)

		for i := 0; i < tau; i++ {

			sharesGen, err := pcgenerator.EvalSeparate(seeds[i], randPolys, ring.Div)
			if err != nil {
				panic(err)
			}
			tuple := sharesGen.GenBBSPlusTuple(root, signerSet)
			tupleArray[j][i] = tuple
		}
	}

	return sk, seeds, tupleArray
}

func GeneratePCFPCGOutputNOutOfN(seedArray [16]uint8, tau int, k int, n int) (*bls12381.Fr, []*pcg.Seed, [][]*pcg.BBSPlusTuple) {
	c, t := 2, 4
	N := 10

	if tau != n {
		panic("threshold must be n")
	}

	pcgenerator, err := pcg.NewPCG(128, N, n, tau, c, t)
	if err != nil {
		panic(err)
	}

	ring, err := pcgenerator.GetRing(false)
	if err != nil {
		panic(err)
	}
	sk, seeds, err := pcgenerator.SeedGenWithSk()
	if err != nil {
		panic(err)
	}
	randPolys, err := pcgenerator.PickRandomPolynomials()
	if err != nil {
		panic(err)
	}
	tupleArray := make([][]*pcg.BBSPlusTuple, k)

	root := ring.Roots[10]

	for j := 0; j < k; j++ {
		tupleArray[j] = make([]*pcg.BBSPlusTuple, tau)

		for i := 0; i < tau; i++ {

			sharesGen, err := pcgenerator.EvalCombined(seeds[i], randPolys, ring.Div)
			if err != nil {
				panic(err)
			}

			tuple := sharesGen.GenBBSPlusTuple(root)
			tupleArray[j][i] = tuple
		}
	}
	return sk, seeds, tupleArray
}

func CreatePPPrecomputation(
	k int,
	n int,
	skShares []*bls12381.Fr,
	aShares, eShares, sShares [][]*bls12381.Fr,
) []*fhksbbsplus.PerPartyPrecomputationsSimple {
	precomputations := make([]*fhksbbsplus.PerPartyPrecomputationsSimple, n)
	for iN := 0; iN < n; iN++ {
		preSignatureList := make([]*fhksbbsplus.PerPartyPreSignatureSimple, k)

		for iK := 0; iK < k; iK++ {

			for jN := 0; jN < n; jN++ {

				preSignatureList[iK] = &fhksbbsplus.PerPartyPreSignatureSimple{
					AShare: aShares[iK][iN],
					EShare: eShares[iK][iN],
					SShare: sShares[iK][iN],
				}
			}
		}

		precomputations[iN] = &fhksbbsplus.PerPartyPrecomputationsSimple{
			Index:         iN,
			SkShare:       skShares[iN],
			PreSignatures: preSignatureList,
		}
	}

	return precomputations
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
