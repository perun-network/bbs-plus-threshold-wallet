package fhks_bbs_plus

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
)

type SecretKey struct {
	*bls12381.Fr
}

type PublicKey struct {
	H0 *bls12381.PointG1
	H  []*bls12381.PointG1
	W  *bls12381.PointG2
}

func (sk *SecretKey) GetPublicKey(messageCount int) *PublicKey {
	return GeneratePublicKeyFromRng(rand.New(rand.NewSource(0)), sk.Fr, messageCount)
}

func (sk *SecretKey) Sign(pk PublicKey, msgs []*bls12381.Fr, e *bls12381.Fr, s *bls12381.Fr) *ThresholdSignature {
	g1 := bls12381.NewG1()
	h0s := g1.New()
	g1.MulScalar(h0s, pk.H0, s)

	capitalA := g1.One()
	g1.Add(capitalA, capitalA, h0s)

	for i, msg := range msgs {
		tmp := g1.New().Set(pk.H[i])
		g1.MulScalar(tmp, tmp, msg)
		g1.Add(capitalA, capitalA, tmp)
	}

	ske := bls12381.NewFr().Set(sk.Fr)
	ske.Add(sk.Fr, e)

	expo := bls12381.NewFr()
	expo.Inverse(ske)

	g1.MulScalar(capitalA, capitalA, expo)

	return &ThresholdSignature{
		CapitalA: capitalA,
		E:        e,
		S:        s,
	}
}
func (pk *PublicKey) Verify(messages []*bls12381.Fr, ts *ThresholdSignature) bool {
	g1 := bls12381.NewG1()

	// Compute h0^S (blinding factor)
	h0s := g1.New().Set(pk.H0)
	g1.MulScalar(h0s, h0s, ts.S)

	// Compute verification basis: H0^S + sum(H_i^m_i)
	verificationBasis := g1.One()
	g1.Add(verificationBasis, verificationBasis, h0s)

	for i, message := range messages {
		tmp := g1.New().Set(pk.H[i])
		g1.MulScalar(tmp, tmp, message) // Multiply H_i by hashed message
		g1.Add(verificationBasis, verificationBasis, tmp)
	}

	// Compute u = W * g_2^E = g_2^sk * g_2^E
	g2 := bls12381.NewG2()
	u := g2.One()
	g2.MulScalar(u, u, ts.E)
	g2.Add(u, u, pk.W)

	// Compute t1 = e(A,u)
	t1 := bls12381.NewEngine().AddPair(ts.CapitalA, u).Result()

	// Compute t2 = e(verificationBasis, g_2)
	t2 := bls12381.NewEngine().AddPair(verificationBasis, g2.One()).Result()

	// Return whether t1 == t2
	return t1.Equal(t2)
}

func GeneratePublicKey(seedArray [16]uint8, sk *bls12381.Fr, messageCount int) *PublicKey {
	seed := int64(binary.BigEndian.Uint64(seedArray[:]))
	rng := rand.New(rand.NewSource(seed))
	return GeneratePublicKeyFromRng(rng, sk, messageCount)
}

func GeneratePublicKeyFromRng(rng *rand.Rand, sk *bls12381.Fr, messageCount int) *PublicKey {
	g2 := bls12381.NewG2()
	w := g2.One()
	g2.MulScalar(w, w, sk)
	allH := make([]*bls12381.PointG1, messageCount+1)

	for i := 0; i <= messageCount; i++ {
		g1 := bls12381.NewG1()
		tmp := g1.One()
		r, err := bls12381.NewFr().Rand(rng)
		if err != nil {
			panic(err)
		}
		g1.MulScalar(tmp, tmp, r)
		allH[i] = tmp
	}

	return &PublicKey{
		W:  w,
		H0: allH[0],
		H:  allH[1:],
	}
}

func (p *PublicKey) MessageCount() int {
	return len(p.H)
}

func GenerateRandomFr() *bls12381.Fr {
	secretKey := bls12381.NewFr()

	_, err := secretKey.Rand(crand.Reader)
	if err != nil {
		panic("failed to generate secret key")
	}

	return secretKey
}

func (pk *PublicKey) Validate() error {
	if pk.H0 == nil || pk.W == nil {
		return errors.New("public key components cannot be nil")
	}

	if bls12381.NewG1().IsZero(pk.H0) || bls12381.NewG2().IsZero(pk.W) {
		return errors.New("public key components cannot be zero")
	}

	for _, v := range pk.H {
		if v == nil || bls12381.NewG1().IsZero(v) {
			return errors.New("public key contains zero or nil elements in H")
		}
	}

	return nil
}
