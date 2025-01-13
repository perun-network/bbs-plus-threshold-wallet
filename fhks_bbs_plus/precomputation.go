package fhks_bbs_plus

import (
	"encoding/binary"
	"errors"
	"fmt"
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

type PerPartyPreSignatureSimple struct {
	AShare     *bls12381.Fr
	EShare     *bls12381.Fr
	SShare     *bls12381.Fr
	AlphaShare *bls12381.Fr
	DeltaShare *bls12381.Fr
}

type PerPartyPrecomputations struct {
	Index         int // Position at which sk-polynomial for own secret key share is evaluated.
	SkShare       *bls12381.Fr
	PreSignatures []*PerPartyPreSignature
}

type PerPartyPrecomputationsWithPubKey struct {
	Index         int // Position at which sk-polynomial for own secret key share is evaluated.
	SkShare       *bls12381.Fr
	PreSignatures []*PerPartyPreSignature
	PublicKey     *bls12381.PointG2
}

func SerializeAeTermsA(aeTermsA []*bls12381.Fr) ([]byte, error) {
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, uint32(len(aeTermsA)))

	var dataBytes []byte
	for _, elem := range aeTermsA {
		dataBytes = append(dataBytes, elem.ToBytes()...)
	}

	return append(lengthBytes, dataBytes...), nil
}
func DeserializeAeTermsA(data []byte) ([]*bls12381.Fr, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short to contain length")
	}

	length := int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]

	elementSize := helper.LenBytesFr
	expectedDataLength := length * elementSize
	if len(data) != expectedDataLength {
		return nil, fmt.Errorf("data length mismatch: expected %d bytes, got %d bytes", expectedDataLength, len(data))
	}

	elements := make([]*bls12381.Fr, length)
	for i := 0; i < length; i++ {
		start := i * elementSize
		end := start + elementSize
		elements[i] = bls12381.NewFr().FromBytes(data[start:end])
	}

	return elements, nil
}
func (ppp *PerPartyPreSignature) ToBytes() ([]byte, error) {
	aShareBytes := ppp.AShare.ToBytes()
	eShareBytes := ppp.EShare.ToBytes()
	sShareBytes := ppp.SShare.ToBytes()
	aeTermOwnBytes := ppp.AeTermOwn.ToBytes()
	asTermOwnBytes := ppp.AsTermOwn.ToBytes()
	askTermOwnBytes := ppp.AskTermOwn.ToBytes()

	serializeFrSlice := func(slice []*bls12381.Fr) ([]byte, error) {
		lengthBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lengthBytes, uint32(len(slice)))

		var data []byte
		for _, elem := range slice {
			data = append(data, elem.ToBytes()...)
		}

		return append(lengthBytes, data...), nil
	}

	aeTermsABytes, err := serializeFrSlice(ppp.AeTermsA)
	if err != nil {
		return nil, err
	}
	aeTermsEBytes, err := serializeFrSlice(ppp.AeTermsE)
	if err != nil {
		return nil, err
	}
	asTermsABytes, err := serializeFrSlice(ppp.AsTermsA)
	if err != nil {
		return nil, err
	}
	asTermsSBytes, err := serializeFrSlice(ppp.AsTermsS)
	if err != nil {
		return nil, err
	}
	askTermsABytes, err := serializeFrSlice(ppp.AskTermsA)
	if err != nil {
		return nil, err
	}
	askTermsSKBytes, err := serializeFrSlice(ppp.AskTermsSK)
	if err != nil {
		return nil, err
	}

	result := append(aShareBytes, eShareBytes...)
	result = append(result, sShareBytes...)
	result = append(result, aeTermOwnBytes...)
	result = append(result, asTermOwnBytes...)
	result = append(result, askTermOwnBytes...)
	result = append(result, aeTermsABytes...)
	result = append(result, aeTermsEBytes...)
	result = append(result, asTermsABytes...)
	result = append(result, asTermsSBytes...)
	result = append(result, askTermsABytes...)
	result = append(result, askTermsSKBytes...)

	return result, nil
}
func FromBytes(data []byte) (*PerPartyPreSignature, *bls12381.Fr, error) {

	readFr := func(data []byte) (*bls12381.Fr, []byte) {
		element := bls12381.NewFr().FromBytes(data[:helper.LenBytesFr])
		copiedElement := bls12381.NewFr()
		copiedElement.Set(element) // Assuming Set() exists for copying values
		return copiedElement, data[helper.LenBytesFr:]
	}

	readFrSlice := func(data []byte) ([]*bls12381.Fr, []byte, error) {
		if len(data) < 4 {
			return nil, nil, errors.New("data too short to contain length")
		}

		length := int(binary.LittleEndian.Uint32(data[:4]))
		data = data[4:]

		elementSize := helper.LenBytesFr
		if len(data) < length*elementSize {
			return nil, nil, errors.New("data too short to contain all elements")
		}

		slice := make([]*bls12381.Fr, length)
		for i := 0; i < length; i++ {
			element := bls12381.NewFr().FromBytes(data[i*elementSize : (i+1)*elementSize])
			copiedElement := bls12381.NewFr()
			copiedElement.Set(element)
			slice[i] = copiedElement
		}

		return slice, data[length*elementSize:], nil
	}

	aShare, data := readFr(data)
	eShare, data := readFr(data)
	sShare, data := readFr(data)
	aeTermOwn, data := readFr(data)
	asTermOwn, data := readFr(data)
	askTermOwn, data := readFr(data)

	var aeTermsA []*bls12381.Fr
	var aeTermsE []*bls12381.Fr
	var asTermsA []*bls12381.Fr
	var asTermsS []*bls12381.Fr
	var askTermsA []*bls12381.Fr
	var askTermsSK []*bls12381.Fr

	var err error

	if aeTermsA, data, err = readFrSlice(data); err != nil {
		return nil, nil, err
	}
	if aeTermsE, data, err = readFrSlice(data); err != nil {
		return nil, nil, err
	}
	if asTermsA, data, err = readFrSlice(data); err != nil {
		return nil, nil, err
	}
	if asTermsS, data, err = readFrSlice(data); err != nil {
		return nil, nil, err
	}
	if askTermsA, data, err = readFrSlice(data); err != nil {
		return nil, nil, err
	}
	if askTermsSK, _, err = readFrSlice(data); err != nil {
		return nil, nil, err
	}

	return &PerPartyPreSignature{
		AShare:     aShare,
		EShare:     eShare,
		SShare:     sShare,
		AeTermOwn:  aeTermOwn,
		AsTermOwn:  asTermOwn,
		AskTermOwn: askTermOwn,
		AeTermsA:   aeTermsA,
		AeTermsE:   aeTermsE,
		AsTermsA:   asTermsA,
		AsTermsS:   asTermsS,
		AskTermsA:  askTermsA,
		AskTermsSK: askTermsSK,
	}, aShare, nil
}

func (ppp *PerPartyPrecomputationsWithPubKey) ToBytes() ([]byte, error) {
	preSigsLenBytes := make([]byte, helper.IntSize)

	binary.LittleEndian.PutUint32(preSigsLenBytes, uint32(len(ppp.PreSignatures)))
	indexBytes := make([]byte, helper.IntSize)
	binary.LittleEndian.PutUint32(indexBytes, uint32(ppp.Index))

	skShareBytes := ppp.SkShare.ToBytes()

	g2 := bls12381.NewG2()
	pkBytes := g2.ToCompressed(ppp.PublicKey)

	bytes := append(skShareBytes, pkBytes...)
	bytes = append(bytes, indexBytes...)

	for _, preSignature := range ppp.PreSignatures {
		asBytes := preSignature.AShare.ToBytes()
		esBytes := preSignature.EShare.ToBytes()
		ssBytes := preSignature.SShare.ToBytes()
		aeBytes := preSignature.AeTermOwn.ToBytes()
		asBytesOwn := preSignature.AsTermOwn.ToBytes()
		askBytes := preSignature.AskTermOwn.ToBytes()

		bytes = append(bytes, asBytes...)
		bytes = append(bytes, esBytes...)
		bytes = append(bytes, ssBytes...)
		bytes = append(bytes, aeBytes...)
		bytes = append(bytes, asBytesOwn...)
		bytes = append(bytes, askBytes...)

		for _, ae := range preSignature.AeTermsA {
			bytes = append(bytes, ae.ToBytes()...)
		}
		for _, ae := range preSignature.AeTermsE {
			bytes = append(bytes, ae.ToBytes()...)
		}
		for _, as := range preSignature.AsTermsA {
			bytes = append(bytes, as.ToBytes()...)
		}
		for _, as := range preSignature.AsTermsS {
			bytes = append(bytes, as.ToBytes()...)
		}
		for _, ask := range preSignature.AskTermsA {
			bytes = append(bytes, ask.ToBytes()...)
		}
		for _, ask := range preSignature.AskTermsSK {
			bytes = append(bytes, ask.ToBytes()...)
		}
	}

	return bytes, nil
}

type PerPartyPrecomputationsSimple struct {
	Index         int // Position at which sk-polynomial for own secret key share is evaluated.
	SkShare       *bls12381.Fr
	PreSignatures []*PerPartyPreSignatureSimple
}
type LivePreSignatureSk struct {
	SkShare    *bls12381.Fr
	AShare     *bls12381.Fr
	EShare     *bls12381.Fr
	SShare     *bls12381.Fr
	DeltaShare *bls12381.Fr
	AlphaShare *bls12381.Fr
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

func (lps *LivePreSignature) FromPreSignatureShares(preSignature *PerPartyPreSignatureSimple) *LivePreSignature {
	livePreSignature := NewLivePreSignature()
	livePreSignature.AShare.Set(preSignature.AShare)
	livePreSignature.EShare.Set(preSignature.EShare)
	livePreSignature.SShare.Set(preSignature.SShare)
	livePreSignature.AlphaShare.Set(preSignature.AlphaShare)
	livePreSignature.DeltaShare.Set(preSignature.DeltaShare)
	return livePreSignature
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
