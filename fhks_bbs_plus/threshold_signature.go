package fhks_bbs_plus

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
)

type ThresholdSignature struct {
	CapitalA *bls12381.PointG1
	E        *bls12381.Fr
	S        *bls12381.Fr
}

func NewThresholdSignature() *ThresholdSignature {
	return &ThresholdSignature{
		CapitalA: bls12381.NewG1().Zero(),
		E:        bls12381.NewFr().Zero(),
		S:        bls12381.NewFr().Zero(),
	}
}
func (s *ThresholdSignature) ToBytes() ([]byte, error) {
	bytes := make([]byte, helper.LenBytesG1Compressed+2*helper.LenBytesFr)

	g1 := bls12381.NewG1()
	aCompressed := g1.ToCompressed(s.CapitalA)

	copy(bytes[:helper.LenBytesG1Compressed], aCompressed)

	eBytes := s.E.ToBytes()
	copy(bytes[helper.LenBytesG1Compressed:helper.LenBytesG1Compressed+helper.LenBytesFr], eBytes)

	sBytes := s.S.ToBytes()
	copy(bytes[helper.LenBytesG1Compressed+helper.LenBytesFr:], sBytes)

	return bytes, nil
}

func ThresholdSignatureFromBytes(data []byte) (*ThresholdSignature, error) {
	if len(data) != helper.LenBytesG1Compressed+2*helper.LenBytesFr {
		return nil, fmt.Errorf("invalid serialized signature length: expected %d, got %d", helper.LenBytesG1Compressed+2*helper.LenBytesFr, len(data))
	}

	g1 := bls12381.NewG1()
	capitalA, err := g1.FromCompressed(data[:helper.LenBytesG1Compressed])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize CapitalA: %v", err)
	}

	e := bls12381.NewFr()
	e.FromBytes(data[helper.LenBytesG1Compressed : helper.LenBytesG1Compressed+helper.LenBytesFr])

	s := bls12381.NewFr()
	s.FromBytes(data[helper.LenBytesG1Compressed+helper.LenBytesFr:])

	return &ThresholdSignature{
		CapitalA: capitalA,
		E:        e,
		S:        s,
	}, nil
}

func (ts *ThresholdSignature) FromPartialSignatures(partialSignatures []*PartialThresholdSignature) *ThresholdSignature {
	g1 := bls12381.NewG1()
	delta := bls12381.NewFr().Zero()
	e := bls12381.NewFr().Zero()
	s := bls12381.NewFr().Zero()
	capitalA := g1.Zero()

	for _, partialSignature := range partialSignatures {
		delta.Add(delta, partialSignature.DeltaShare)
		e.Add(e, partialSignature.EShare)
		s.Add(s, partialSignature.SShare)
		g1.Add(capitalA, capitalA, partialSignature.CapitalAShare)
	}

	epsilon := bls12381.NewFr()
	epsilon.Inverse(delta)

	g1.MulScalar(capitalA, capitalA, epsilon)

	ts.CapitalA.Set(capitalA)
	ts.E.Set(e)
	ts.S.Set(s)
	return ts
}

func (ts *ThresholdSignature) FromSecretKey(
	pk *PublicKey,
	sk *bls12381.Fr,
	e *bls12381.Fr,
	s *bls12381.Fr,
	messages []*bls12381.Fr,
) *ThresholdSignature {
	g1 := bls12381.NewG1()
	h0s := g1.New().Set(pk.H0)
	g1.MulScalar(h0s, h0s, s)
	capitalA := g1.One()
	g1.Add(capitalA, capitalA, h0s)

	for i, message := range messages {
		tmp := g1.New().Set(pk.H[i])
		g1.MulScalar(tmp, tmp, message)
		g1.Add(capitalA, capitalA, tmp)
	}

	ske := bls12381.NewFr().Set(sk)
	ske.Add(sk, e)

	expo := bls12381.NewFr()
	expo.Inverse(ske)

	g1.MulScalar(capitalA, capitalA, expo)

	ts.CapitalA.Set(capitalA)
	ts.E.Set(e)
	ts.S.Set(s)
	return ts
}

func (ts *ThresholdSignature) Verify(messages []*bls12381.Fr, pk *PublicKey) bool {
	g1 := bls12381.NewG1()
	h0s := g1.New().Set(pk.H0)
	g1.MulScalar(h0s, h0s, ts.S)

	verificationBasis := g1.One()
	g1.Add(verificationBasis, verificationBasis, h0s)
	for i, message := range messages {
		tmp := g1.New().Set(pk.H[i])
		g1.MulScalar(tmp, tmp, message)
		g1.Add(verificationBasis, verificationBasis, tmp)
	}

	// Compute u = w * g_2^e = g_2^sk * g_2^e
	g2 := bls12381.NewG2()
	u := g2.One()
	g2.MulScalar(u, u, ts.E)
	g2.Add(u, u, pk.W)

	// Compute t1 = e(A,u)
	t1 := bls12381.NewEngine().AddPair(ts.CapitalA, u).Result()

	//Different basis
	//Compute t2 = e(basis, g_2)
	t2 := bls12381.NewEngine().AddPair(verificationBasis, g2.One()).Result()

	return t1.Equal(t2)
}
