package fhks_bbs_plus_test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation"
	"testing"

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

func TestSimpleSigningMockedPre(t *testing.T) {
	messages := helper.GetRandomMessagesFromSeed(seedMessages, test.K, messageCount)

	sk, preComputation := precomputation.GeneratePPPrecomputationMock(seedPresignatures, test.Threshold, test.K, test.N)

	pk := fhks_bbs_plus.GeneratePublicKey(seedKeys, sk, messageCount)

	for iK := 0; iK < test.K; iK++ {
		partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, test.Threshold)
		for iT := 0; iT < test.Threshold; iT++ {
			ownIndex := test.IndicesSimple[iK][iT]
			x := fhks_bbs_plus.NewPartialThresholdSignature().New(
				messages[iK],
				pk,
				fhks_bbs_plus.NewLivePreSignature().FromPreSignature(
					ownIndex,
					test.IndicesSimple[iK],
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

func TestSimpleSigningTauOutOfN(t *testing.T) {

	messages := helper.GetRandomMessagesFromSeed(seedMessages, test.K, messageCount)

	sk, preComputation := precomputation.GeneratePPPrecomputationTauOutOfN(seedPresignatures, test.Threshold, test.K, test.N)

	pk := fhks_bbs_plus.GeneratePublicKey(seedKeys, sk, messageCount)

	// for K no of messages to sign for signers test.Threshold
	for iK := 0; iK < test.K; iK++ {
		partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, test.Threshold)
		for iT := 0; iT < test.Threshold; iT++ {
			freshPreSig := fhks_bbs_plus.NewLivePreSignature()
			Akt := preComputation[iK][iT].AShare
			Ekt := preComputation[iK][iT].EShare
			Skt := preComputation[iK][iT].SShare
			pppSigSimple := fhks_bbs_plus.PerPartyPreSignatureSimple{
				AShare: Akt,
				EShare: Ekt,
				SShare: Skt,
			}
			filledPreSig := freshPreSig.FromPreSignatureShares(&pppSigSimple)

			x := fhks_bbs_plus.NewPartialThresholdSignature().New(
				messages[iK],
				pk,
				filledPreSig,
			)

			partialSignatures[iT] = x
		}
		signature := fhks_bbs_plus.NewThresholdSignature().FromPartialSignatures(partialSignatures)

		if !signature.Verify(messages[iK], pk) {
			t.Errorf("Signature verification failed")
		}
	}
}
