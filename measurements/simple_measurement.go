package measurements

import (
	"fmt"
	"time"

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
	messageCount = 1 // Number of messages to be created

	t       = 8  // Security threshold (t-out-of-n)
	n       = 10 // Number of servers
	k       = 3  // Presignature to create
	indices = [][]int{
		{1, 4, 3, 5, 7, 6, 8, 10},
		{1, 3, 8, 9, 4, 10, 5, 2},
		{2, 4, 5, 1, 3, 6, 7, 8}}
)

func SimpleMeasurementWithCoefficientComputation() {
	var makeLiveDurations []time.Duration
	var thresholdSignDurations []time.Duration
	var reconstructDurations []time.Duration
	var verifyDurations []time.Duration
	var directSignDurations []time.Duration

	messages := helper.GetRandomMessagesFromSeed(seedMessages, messageCount, k)

	directES := helper.GetRandomMessagesFromSeed(seedKeys, 2, k)

	sk, preComputation := precomputation_mockup.GeneratePPPrecomputation(
		seedPresignatures, t, n, k)

	pk := fhks_bbs_plus.GeneratePublicKey(seedKeys, sk, messageCount)

	for iK := 0; iK < k; iK++ {
		var partialSignatures []*fhks_bbs_plus.PartialThresholdSignature
		for iT := 0; iT < t; iT++ {
			ownIndex := indices[iK][iT]
			start := time.Now()
			livePresignature := fhks_bbs_plus.NewLivePreSignature().FromPreSignature(
				ownIndex,
				indices[iK],
				preComputation[ownIndex-1].PreSignatures[iK],
			)
			makeLiveDurations = append(makeLiveDurations, time.Since(start))
			start = time.Now()
			partialThresholdSignature := fhks_bbs_plus.NewPartialThresholdSignature().New(
				messages[iK],
				pk,
				livePresignature,
			)
			thresholdSignDurations = append(thresholdSignDurations, time.Since(start))
			partialSignatures = append(partialSignatures, partialThresholdSignature)
		}

		start := time.Now()
		signature := fhks_bbs_plus.NewThresholdSignature().FromPartialSignatures(partialSignatures)
		reconstructDurations = append(reconstructDurations, time.Since(start))

		start = time.Now()
		if !signature.Verify(messages[iK], pk) {
			panic("signature verification failed")
		}
		verifyDurations = append(verifyDurations, time.Since(start))

		start = time.Now()
		signature = fhks_bbs_plus.NewThresholdSignature().FromSecretKey(
			pk,
			sk,
			directES[iK][0],
			directES[iK][1],
			messages[iK],
		)
		directSignDurations = append(directSignDurations, time.Since(start))

		start = time.Now()
		if !signature.Verify(messages[iK], pk) {
			panic("directly generated signature verification failed")
		}
		verifyDurations = append(verifyDurations, time.Since(start))
	}

	fmt.Println("makeLiveDurations:", makeLiveDurations)
	fmt.Println("thresholdSignDurations:", thresholdSignDurations)
	fmt.Println("reconstructDurations:", reconstructDurations)
	fmt.Println("verifyDurations:", verifyDurations)
	fmt.Println("directSignDurations:", directSignDurations)
}
