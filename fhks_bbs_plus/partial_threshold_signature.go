package fhks_bbs_plus

import (
	"errors"

	bls12381 "github.com/kilic/bls12-381"
)

type PartialThresholdSignature struct {
	CapitalAShare *bls12381.PointG1
	DeltaShare    *bls12381.Fr
	EShare        *bls12381.Fr
	SShare        *bls12381.Fr
}

func NewPartialThresholdSignature() *PartialThresholdSignature {
	return &PartialThresholdSignature{
		CapitalAShare: bls12381.NewG1().Zero(),
		DeltaShare:    bls12381.NewFr().Zero(),
		EShare:        bls12381.NewFr().Zero(),
		SShare:        bls12381.NewFr().Zero(),
	}
}

func NewPartialThresholdSignatureFromValues(capitalAShare *bls12381.PointG1, deltaShare, eShare, sShare *bls12381.Fr) *PartialThresholdSignature {
	return &PartialThresholdSignature{
		CapitalAShare: capitalAShare,
		DeltaShare:    deltaShare,
		EShare:        eShare,
		SShare:        sShare,
	}
}

func (pts *PartialThresholdSignature) New(messages []*bls12381.Fr, pk *PublicKey, preSignature *LivePreSignature) *PartialThresholdSignature {
	// message-dependent term
	g1 := bls12381.NewG1()
	basis := bls12381.NewG1().One()

	for i := 0; i < len(pk.H); i++ {
		tmp := g1.New().Set(pk.H[i])
		g1.MulScalar(tmp, tmp, messages[i])
		g1.Add(basis, basis, tmp)
	}

	// Share of A
	capitalAShare := g1.New().Set(basis)
	g1.MulScalar(capitalAShare, capitalAShare, preSignature.AShare)
	tmp := g1.New().Set(pk.H0)
	g1.MulScalar(tmp, tmp, preSignature.AlphaShare)
	g1.Add(capitalAShare, capitalAShare, tmp)

	pts.CapitalAShare.Set(capitalAShare)
	pts.DeltaShare.Set(preSignature.DeltaShare)
	pts.EShare.Set(preSignature.EShare)
	pts.SShare.Set(preSignature.SShare)
	return pts
}

func (pts *PartialThresholdSignature) ToBytes() ([]byte, error) {
	// Serialize CapitalAShare
	g1 := bls12381.NewG1()
	cAShareBytes := g1.ToBytes(pts.CapitalAShare)

	// Serialize DeltaShare
	deltaShareBytes := pts.DeltaShare.ToBytes()

	// Serialize EShare
	eShareBytes := pts.EShare.ToBytes()

	// Serialize SShare
	sShareBytes := pts.SShare.ToBytes()

	serialized := append(cAShareBytes, deltaShareBytes...)
	serialized = append(serialized, eShareBytes...)
	serialized = append(serialized, sShareBytes...)
	if len(serialized) < G1Size+FrSize*3 {
		return nil, errors.New("outputput data is too short to represent the PartialThresholdSignature")
	}
	return serialized, nil
}

func (pts *PartialThresholdSignature) FromBytes(data []byte) error {
	if len(data) < G1Size+FrSize*3 {
		return errors.New("input data is too short to represent the PartialThresholdSignature")
	}

	// Deserialize CapitalAShare
	cAShareBytes := data[:G1Size]
	g1 := bls12381.NewG1()
	cAShare, err := g1.FromBytes(cAShareBytes)
	if err != nil {
		return err
	}

	// Deserialize DeltaShare
	deltaShareBytes := data[G1Size : G1Size+FrSize]
	deltaShare := bls12381.NewFr().FromBytes(deltaShareBytes)

	// Deserialize EShare
	eShareBytes := data[G1Size+FrSize : G1Size+FrSize*2]
	eShare := bls12381.NewFr().FromBytes(eShareBytes)

	// Deserialize SShare
	sShareBytes := data[G1Size+FrSize*2 : G1Size+FrSize*3]
	sShare := bls12381.NewFr().FromBytes(sShareBytes)

	pts.CapitalAShare = cAShare
	pts.DeltaShare = deltaShare
	pts.EShare = eShare
	pts.SShare = sShare

	return nil
}
