package test

import (
	"testing"

	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation_mockup"
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

func TestSimpleSigning(t *testing.T) {
	messages := helper.GetRandomMessagesFromSeed(seedMessages, messageCount, k)

	sk, preComputation := precomputation_mockup.GeneratePPPrecomputation(seedPresignatures, threshold, n, k)

	pk := fhks_bbs_plus.GeneratePublicKey(seedKeys, sk, messageCount)

	for iK := 0; iK < k; iK++ {
		partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, threshold)
		for iT := 0; iT < threshold; iT++ {
			ownIndex := indices[iK][iT]
			x := fhks_bbs_plus.NewPartialThresholdSignature().New(
				messages[iK],
				pk,
				fhks_bbs_plus.NewLivePreSignature().FromPreSignature(
					ownIndex,
					indices[iK],
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
