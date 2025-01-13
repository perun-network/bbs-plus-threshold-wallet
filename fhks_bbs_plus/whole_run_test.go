package fhks_bbs_plus_test

import (
	"testing"

	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"

	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation"

	"github.com/perun-network/bbs-plus-threshold-wallet/test"
)

func TestSimpleSigningMockedPre(t *testing.T) {
	messages := helper.GetRandomMessagesFromSeed(test.SeedMessages, test.K, test.MessageCount)

	sk, preComputation := precomputation.GeneratePPPrecomputationMock(test.SeedPresignatures, test.Threshold, test.K, test.N)

	pk := fhks_bbs_plus.GeneratePublicKey(test.SeedKeys, sk, test.MessageCount)

	for iK := 0; iK < test.K; iK++ {
		partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, test.Threshold)
		for iT := 0; iT < test.Threshold; iT++ {
			ownIndex := test.Indices[iK][iT]
			x := fhks_bbs_plus.NewPartialThresholdSignature().New(
				messages[iK],
				pk,
				fhks_bbs_plus.NewLivePreSignature().FromPreSignature(
					ownIndex,
					test.Indices[iK],
					preComputation[ownIndex-1].PreSignatures[iK],
				),
			)
			partialSignatures[iT] = x
		}
		signature := fhks_bbs_plus.NewThresholdSignature().FromPartialSignatures(partialSignatures)

		if !signature.Verify(messages[iK], pk) {
			t.Errorf("Signature verification failed")
		}
	}
}

func TestSimpleSigningNOutOfN(t *testing.T) {

	messages := helper.GetRandomMessagesFromSeed(test.SeedMessages, test.K, test.MessageCount)

	sk, skSeeds, preComputation := precomputation.GeneratePPPrecomputationNOutOfN(test.SeedPresignatures, test.N, test.K, test.N)

	for j := 0; j < test.K; j++ {
		totalSkShare := bls12381.NewFr()
		totalAShare := bls12381.NewFr()
		totalSShare := bls12381.NewFr()
		totalEShare := bls12381.NewFr()
		totalAlphaShare := bls12381.NewFr()
		totalDeltaShare := bls12381.NewFr()
		seedSk := bls12381.NewFr()

		for i := 0; i < test.N; i++ {
			preComp := preComputation[j][i]
			totalSkShare.Add(totalSkShare, preComp.SkShare)
			totalAShare.Add(totalAShare, preComp.AShare)
			totalSShare.Add(totalSShare, preComp.SShare)
			totalEShare.Add(totalEShare, preComp.EShare)
			totalAlphaShare.Add(totalAlphaShare, preComp.AlphaShare)
			totalDeltaShare.Add(totalDeltaShare, preComp.DeltaShare)
			seedSk.Add(seedSk, skSeeds[i].GetSki())
		}

		// compare result
		assert.Equal(t, 0, totalSkShare.Cmp(seedSk))
		ask := bls12381.NewFr() // = delta0
		ask.Mul(totalAShare, totalSkShare)

		ae := bls12381.NewFr() // = delta1
		ae.Mul(totalAShare, totalEShare)

		// // Check if correlations hold
		askPae := bls12381.NewFr() // = a(sk + e)
		askPae.Add(ask, ae)
		assert.Equal(t, 0, totalDeltaShare.Cmp(askPae))

		as := bls12381.NewFr()
		as.Mul(totalAShare, totalSShare)
		assert.Equal(t, 0, totalAlphaShare.Cmp(as))
	}

	pk := fhks_bbs_plus.GeneratePublicKey(test.SeedKeys, sk, test.MessageCount)

	// for K no of messages to sign for signers test.Threshold, with N signers because tau == N
	for iK := 0; iK < test.K; iK++ {
		partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, test.N)
		for iT := 0; iT < test.N; iT++ {

			emptyPreSig := fhks_bbs_plus.NewLivePreSignature()

			ppPreSigSimple := fhks_bbs_plus.PerPartyPreSignatureSimple{
				AShare:     preComputation[iK][iT].AShare,
				EShare:     preComputation[iK][iT].EShare,
				SShare:     preComputation[iK][iT].SShare,
				AlphaShare: preComputation[iK][iT].AlphaShare,
				DeltaShare: preComputation[iK][iT].DeltaShare,
			}
			preSig := emptyPreSig.FromPreSignatureShares(&ppPreSigSimple)
			x := fhks_bbs_plus.NewPartialThresholdSignature().New(
				messages[iK],
				pk,
				preSig,
			)
			partialSignatures[iT] = x
		}
		signature := fhks_bbs_plus.NewThresholdSignature().FromPartialSignatures(partialSignatures)

		if !signature.Verify(messages[iK], pk) {
			t.Errorf("Signature verification failed")
		}
	}
}
