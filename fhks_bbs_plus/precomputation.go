package fhks_bbs_plus

import (
	"encoding/binary"
	"errors"

	bls12381 "github.com/kilic/bls12-381"

	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
)

type PerPartyPreSignature struct {
	AShare     *bls12381.Fr   // a^k_i for k in [t].
	EShare     *bls12381.Fr   // e^k_i for k in [t].
	SShare     *bls12381.Fr   // s^k_i for k in [t].
	AeTermOwn  *bls12381.Fr   // a^k_i * e^k_i for k in [t].   // Might not be necessary.
	AsTermOwn  *bls12381.Fr   // a^k_i * s^k_i for k in [t]   // Might not be necessary.
	AskTermOwn *bls12381.Fr   // a^k_i * sk_i for k in [t]    // Might not be necessary.
	AeTermsA   []*bls12381.Fr // Share of a^k_i * e^k_j for k in [t], j in [n] (j can also be i).
	AeTermsE   []*bls12381.Fr // Share of a^k_j * e^k_i for k in [t], j in [n] (j can also be i -- this time other share).
	AsTermsA   []*bls12381.Fr // Share of a^k_i * s^k_j for k in [t], j in [n] (j can also be i).
	AsTermsS   []*bls12381.Fr // Share of a^k_j * s^k_i for k in [t], j in [n] (j can also be i -- this time other share).
	AskTermsA  []*bls12381.Fr // Share of a^k_i * sk_j for k in [t], j in [n] (j can also be i).
	AskTermsSK []*bls12381.Fr // Share of a^k_j * sk_i for k in [t], j in [n] (j can also be i -- this time other share).
}

func (ppps *PerPartyPreSignature) ToBytes() ([]byte, error) {

	// Serialize AShare
	aShareBytes := ppps.AShare.ToBytes()

	// Serialize EShare
	eShareBytes := ppps.EShare.ToBytes()

	// Serialize sShare
	sShareBytes := ppps.SShare.ToBytes()

	// Serialize AeTermOwn
	aeTermOwnBytes := ppps.AeTermOwn.ToBytes()

	// Serialize AsTermOwn
	asTermOwnBytes := ppps.AsTermOwn.ToBytes()

	// Serialize AskTermOwn
	askTermOwnBytes := ppps.AskTermOwn.ToBytes()

	// Serialize AeTermsA
	aeTermsALenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(aeTermsALenBytes, uint32(len(ppps.AeTermsA)))
	var aeTermsABytes []byte
	for _, aeTermA := range ppps.AeTermsA {
		aeTermsABytes = append(aeTermsABytes, aeTermA.ToBytes()...)
	}

	// Serialize AeTermsE
	aeTermsELenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(aeTermsELenBytes, uint32(len(ppps.AeTermsE)))
	var aeTermsEBytes []byte
	for _, aeTermE := range ppps.AeTermsE {
		aeTermsEBytes = append(aeTermsEBytes, aeTermE.ToBytes()...)
	}
	// Serialize AsTermsA
	asTermsALenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(asTermsALenBytes, uint32(len(ppps.AsTermsA)))
	var asTermsABytes []byte
	for _, asTermA := range ppps.AsTermsA {
		asTermsABytes = append(asTermsABytes, asTermA.ToBytes()...)
	}

	// Serialize AsTermsS
	asTermsSLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(asTermsSLenBytes, uint32(len(ppps.AsTermsS)))
	var asTermsSBytes []byte
	for _, asTermS := range ppps.AsTermsS {
		asTermsSBytes = append(asTermsSBytes, asTermS.ToBytes()...)
	}

	// Serialize AskTermsA
	askTermsALenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(askTermsALenBytes, uint32(len(ppps.AskTermsA)))
	var askTermsABytes []byte
	for _, askTermA := range ppps.AskTermsA {
		askTermsABytes = append(askTermsABytes, askTermA.ToBytes()...)
	}

	// Serialize AskTermsSK
	askTermsSKLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(askTermsSKLenBytes, uint32(len(ppps.AskTermsSK)))
	var askTermsSKBytes []byte
	for _, askTermSK := range ppps.AskTermsSK {
		askTermsSKBytes = append(askTermsSKBytes, askTermSK.ToBytes()...)
	}

	serialized := append(aeTermsALenBytes, aeTermsELenBytes...)
	serialized = append(serialized, asTermsALenBytes...)
	serialized = append(serialized, asTermsSLenBytes...)
	serialized = append(serialized, askTermsALenBytes...)
	serialized = append(serialized, askTermsSKLenBytes...)
	serialized = append(serialized, aShareBytes...)
	serialized = append(serialized, eShareBytes...)
	serialized = append(serialized, sShareBytes...)
	serialized = append(serialized, aeTermOwnBytes...)
	serialized = append(serialized, asTermOwnBytes...)
	serialized = append(serialized, askTermOwnBytes...)
	serialized = append(serialized, aeTermsABytes...)
	serialized = append(serialized, aeTermsEBytes...)
	serialized = append(serialized, asTermsABytes...)
	serialized = append(serialized, asTermsSBytes...)
	serialized = append(serialized, askTermsABytes...)
	serialized = append(serialized, askTermsSKBytes...)

	if len(serialized) < 4*6+FrSize*
		(6+len(ppps.AeTermsA)+len(ppps.AeTermsE)+
			len(ppps.AsTermsA)+len(ppps.AsTermsS)+
			len(ppps.AskTermsA)+len(ppps.AskTermsSK)) {
		return nil, errors.New("output data is too short to represent the PerPartyPreSignature")
	}
	return serialized, nil
}

func (ppps *PerPartyPreSignature) FromBytes(data []byte) error {
	if len(data) < 6*4 {
		return errors.New("input data is too short to represent the PerPartyPreSignature")
	}

	// Deserialize slices' lengths
	aeTermsALen := int(binary.LittleEndian.Uint32(data[:4]))
	aeTermsELen := int(binary.LittleEndian.Uint32(data[4:8]))
	asTermsALen := int(binary.LittleEndian.Uint32(data[8:12]))
	asTermsSLen := int(binary.LittleEndian.Uint32(data[12:16]))
	askTermsALen := int(binary.LittleEndian.Uint32(data[16:20]))
	askTermsSKLen := int(binary.LittleEndian.Uint32(data[20:24]))

	data = data[24:]
	if len(data) < FrSize*
		(6+aeTermsALen+aeTermsELen+
			asTermsALen+asTermsSLen+
			askTermsALen+askTermsSKLen) {
		return errors.New("input data is too short to represent the PerPartyPreSignature")
	}

	// Deserialize AShare
	aShareBytes := data[:FrSize]
	data = data[FrSize:]
	aShare := bls12381.NewFr().FromBytes(aShareBytes)

	// Deserialize EShare
	eShareBytes := data[:FrSize]
	data = data[FrSize:]
	eShare := bls12381.NewFr().FromBytes(eShareBytes)

	// Deserialize SShare
	sShareBytes := data[:FrSize]
	data = data[FrSize:]
	sShare := bls12381.NewFr().FromBytes(sShareBytes)

	// Deserialize AeTermOwn
	aeTermOwnBytes := data[:FrSize]
	data = data[FrSize:]
	aeTermOwn := bls12381.NewFr().FromBytes(aeTermOwnBytes)

	// Deserialize AsTermOwn
	asTermOwnBytes := data[:FrSize]
	data = data[FrSize:]
	asTermOwn := bls12381.NewFr().FromBytes(asTermOwnBytes)

	// Deserialize AskTermOwn
	askTermOwnBytes := data[:FrSize]
	data = data[FrSize:]
	askTermOwn := bls12381.NewFr().FromBytes(askTermOwnBytes)

	// Deserialise AeTermsA
	aeTermsABytes := data[:FrSize*aeTermsALen]
	data = data[FrSize*aeTermsALen:]
	aeTermsA := make([]*bls12381.Fr, aeTermsALen)
	for i := 0; i < aeTermsALen; i++ {
		offset := i * FrSize
		aeTermABytes := aeTermsABytes[offset : offset+FrSize]
		aeTermsA[i] = bls12381.NewFr().FromBytes(aeTermABytes)
	}

	// Deserialise AeTermsE
	aeTermsEBytes := data[:FrSize*aeTermsELen]
	data = data[FrSize*aeTermsELen:]
	aeTermsE := make([]*bls12381.Fr, aeTermsELen)
	for i := 0; i < aeTermsELen; i++ {
		offset := i * FrSize
		aeTermEBytes := aeTermsEBytes[offset : offset+FrSize]
		aeTermsE[i] = bls12381.NewFr().FromBytes(aeTermEBytes)
	}

	// Deserialise AsTermsA
	asTermsABytes := data[:FrSize*asTermsALen]
	data = data[FrSize*asTermsALen:]
	asTermsA := make([]*bls12381.Fr, asTermsALen)
	for i := 0; i < asTermsALen; i++ {
		offset := i * FrSize
		asTermABytes := asTermsABytes[offset : offset+FrSize]
		asTermsA[i] = bls12381.NewFr().FromBytes(asTermABytes)
	}

	// Deserialise AsTermsS
	asTermsSBytes := data[:FrSize*asTermsSLen]
	data = data[FrSize*asTermsSLen:]
	asTermsS := make([]*bls12381.Fr, asTermsSLen)
	for i := 0; i < asTermsSLen; i++ {
		offset := i * FrSize
		asTermSBytes := asTermsSBytes[offset : offset+FrSize]
		asTermsS[i] = bls12381.NewFr().FromBytes(asTermSBytes)
	}

	// Deserialise AskTermsA
	askTermsABytes := data[:FrSize*askTermsALen]
	data = data[FrSize*askTermsALen:]
	askTermsA := make([]*bls12381.Fr, askTermsALen)
	for i := 0; i < askTermsALen; i++ {
		offset := i * FrSize
		askTermABytes := askTermsABytes[offset : offset+FrSize]
		askTermsA[i] = bls12381.NewFr().FromBytes(askTermABytes)
	}
	// Deserialise AskTermsSK
	askTermsSKBytes := data[:FrSize*askTermsSKLen]
	askTermsSK := make([]*bls12381.Fr, askTermsSKLen)
	for i := 0; i < askTermsSKLen; i++ {
		offset := i * FrSize
		askTermSKBytes := askTermsSKBytes[offset : offset+FrSize]
		askTermsSK[i] = bls12381.NewFr().FromBytes(askTermSKBytes)
	}

	ppps.AShare = aShare
	ppps.EShare = eShare
	ppps.SShare = sShare
	ppps.AeTermOwn = aeTermOwn
	ppps.AsTermOwn = asTermOwn
	ppps.AskTermOwn = askTermOwn
	ppps.AeTermsA = aeTermsA
	ppps.AeTermsE = aeTermsE
	ppps.AsTermsA = asTermsA
	ppps.AsTermsS = asTermsS
	ppps.AskTermsA = askTermsA
	ppps.AskTermsSK = askTermsSK

	return nil
}

type PerPartyPrecomputations struct {
	Index         int // Position at which sk-polynomial for own secret key share is evaluated.
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

	// For (ae,as = alpha)-shares start with the multiplication of both own shares
	alphaShare := bls12381.NewFr().Set(preSignature.AsTermOwn)
	aeShare := bls12381.NewFr().Set(preSignature.AeTermOwn)

	// ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets
	// other-index-lagrange.
	askShare := bls12381.NewFr().Zero()
	tmpAskOwnCoefficient := bls12381.NewFr().Set(preSignature.AskTermOwn)

	indI := 0
	for indJ, elJ := range indices {
		if elJ != ownIndex {
			// Add shares of a_i * e/s_j (ae/s_terms_a), a_j * e_i (ae/s_terms_a/s)
			aeShare.Add(aeShare, preSignature.AeTermsA[elJ-1])
			aeShare.Add(aeShare, preSignature.AeTermsE[elJ-1])
			alphaShare.Add(alphaShare, preSignature.AsTermsA[elJ-1])
			alphaShare.Add(alphaShare, preSignature.AsTermsS[elJ-1])

			// Share of  a_i * sk_j (using j's lagrange coefficient) is added to share_of_ask
			tmp := bls12381.NewFr().Set(preSignature.AskTermsA[elJ-1])
			tmp.Mul(tmp, lagrangeCoefficients[indJ])

			askShare.Add(askShare, tmp)

			// Share of a_j * sk_i (using i's lagrange coefficient) is added to tmp_ask_own_lagrange (coefficient is
			// applied later for all at once).
			tmpAskOwnCoefficient.Add(tmpAskOwnCoefficient, preSignature.AskTermsSK[elJ-1])
		} else {
			indI = indJ
		}
	}
	// Apply i's lagrange coefficient to sum of share of all cross-terms incorporating sk_i and add result to share of ask.
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
