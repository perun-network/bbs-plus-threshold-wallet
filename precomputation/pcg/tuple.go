package pcg

import (
	"bytes"
	"encoding/gob"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation/pcg/poly"
)

// BBSPlusTupleGenerator holds the polynomials from which pre-computed BBS+ signatures can be derived.
// It is used for the n-out-of-n scheme.
type BBSPlusTupleGenerator struct {
	skShare    *bls12381.Fr
	aPoly      *poly.Polynomial
	ePoly      *poly.Polynomial
	sPoly      *poly.Polynomial
	alphaPoly  *poly.Polynomial
	delta0Poly *poly.Polynomial
	delta1Poly *poly.Polynomial
	deltaPoly  *poly.Polynomial
}

// NewBBSPlusTupleGenerator returns a new BBSPlusTupleGenerator for an n-out-of-n scheme.
func NewBBSPlusTupleGenerator(SkShare *bls12381.Fr, APoly, EPoly, SPoly, AlphaPoly, Delta0Poly, Delta1Poly *poly.Polynomial) *BBSPlusTupleGenerator {
	return &BBSPlusTupleGenerator{
		skShare:    SkShare,
		aPoly:      APoly,
		ePoly:      EPoly,
		sPoly:      SPoly,
		alphaPoly:  AlphaPoly,
		delta0Poly: Delta0Poly, // Store delta0Poly and delta1Poly separately for testing purposes.
		delta1Poly: Delta1Poly,
		deltaPoly:  poly.Add(Delta0Poly, Delta1Poly),
	}
}

// GenBBSPlusTuple returns a BBSPlusTuple from a BBSPlusTupleGenerator for a given root.
func (t *BBSPlusTupleGenerator) GenBBSPlusTuple(root *bls12381.Fr) *BBSPlusTuple {
	aiElement := t.aPoly.Evaluate(root)
	eiElement := t.ePoly.Evaluate(root)
	siElement := t.sPoly.Evaluate(root)
	alphaiElement := t.alphaPoly.Evaluate(root)

	deltaiElement := t.deltaPoly.Evaluate(root)

	return NewBBSPlusTuple(t.skShare, aiElement, eiElement, siElement, alphaiElement, deltaiElement)
}

// BBSPlusTupleGenerator holds the polynomials from which pre-computed BBS+ signatures can be derived.
// It is used for the tau-out-of-n scheme.
type SeparateBBSPlusTupleGenerator struct {
	ownIndex   int // signer index of the participant
	n          int // number of participants
	usk        *poly.Polynomial
	uk         *poly.Polynomial
	uv         *poly.Polynomial
	skShare    *bls12381.Fr
	aPoly      *poly.Polynomial
	ePoly      *poly.Polynomial
	sPoly      *poly.Polynomial
	alphaPoly  []*poly.Polynomial
	delta0Poly [][]*poly.Polynomial
	delta1Poly []*poly.Polynomial
}

func (t *SeparateBBSPlusTupleGenerator) OwnIndex() int {
	return t.ownIndex
}

// NewSeparateBBSPlusTupleGenerator returns a new NewSeparateBBSPlusTupleGenerator for an tau-out-of-n scheme.
func NewSeparateBBSPlusTupleGenerator(usk, uk, uv *poly.Polynomial, SkShare *bls12381.Fr, APoly, EPoly, SPoly *poly.Polynomial, Delta0Poly [][]*poly.Polynomial, AlphaPoly, Delta1Poly []*poly.Polynomial) *SeparateBBSPlusTupleGenerator {
	n := len(Delta1Poly)
	var ownIndex int
	for i := 0; i < n; i++ {
		if Delta1Poly[i] == nil {
			ownIndex = i
			break
		}
	}

	return &SeparateBBSPlusTupleGenerator{
		ownIndex:   ownIndex,
		n:          n,
		usk:        usk,
		uk:         uk,
		uv:         uv,
		skShare:    SkShare,
		aPoly:      APoly,
		ePoly:      EPoly,
		sPoly:      SPoly,
		alphaPoly:  AlphaPoly,
		delta0Poly: Delta0Poly,
		delta1Poly: Delta1Poly,
	}
}

// GenBBSPlusTuple returns a BBSPlusTuple from a SeparateBBSPlusTupleGenerator for a given root.
// signerSet is the set of signers that are participating. It must contain ownIndex.
func (t *SeparateBBSPlusTupleGenerator) GenBBSPlusTupleNoLagrange(root *bls12381.Fr, signerSet []int) *BBSPlusTuple {
	// Check if ownIndex is in signerSet
	ownIndexInSignerSet := false
	for _, signer := range signerSet {
		if signer == t.ownIndex {
			ownIndexInSignerSet = true
			break
		}
	}
	if !ownIndexInSignerSet {
		return nil
	}

	// Calculate a_i
	aiElement := t.aPoly.Evaluate(root)

	// Calculate e_i
	eiElement := t.ePoly.Evaluate(root)

	// Calculate s_i
	siElement := t.sPoly.Evaluate(root)

	// Calculate delta_0i based on the signer set

	delta0i := poly.NewEmpty()
	for _, signer := range signerSet {
		if signer != t.ownIndex {
			delta0i.Add(t.delta0Poly[signer][forwardDirection])
			delta0i.Add(t.delta0Poly[signer][backwardDirection])
		}
	}
	delta0i.Add(t.usk)

	// Calculate alpha_i based on the signer set
	alphai := poly.NewEmpty()
	for _, signer := range signerSet {
		if signer != t.ownIndex {
			alphai.Add(t.alphaPoly[signer])
		}
	}
	alphai.Add(t.uk)
	alphaiElement := alphai.Evaluate(root)

	// Calculate delta_1i based on the signer set
	delta1i := poly.NewEmpty()
	for _, signer := range signerSet {
		if signer != t.ownIndex {
			delta1i.Add(t.delta1Poly[signer])
		}
	}
	delta1i.Add(t.uv)

	deltaiPoly := poly.Add(delta0i, delta1i)
	deltaiElement := deltaiPoly.Evaluate(root)

	return NewBBSPlusTuple(t.skShare, aiElement, eiElement, siElement, alphaiElement, deltaiElement)
}

// GenBBSPlusTuple returns a BBSPlusTuple from a SeparateBBSPlusTupleGenerator for a given root.
// signerSet is the set of signers that are participating. It must contain ownIndex.
func (t *SeparateBBSPlusTupleGenerator) GenBBSPlusTuple(root *bls12381.Fr, signerSet []int) *BBSPlusTuple {
	// Check if ownIndex is in signerSet
	ownIndexInSignerSet := false
	for _, signer := range signerSet {
		if signer == t.ownIndex {
			ownIndexInSignerSet = true
			break
		}
	}
	if !ownIndexInSignerSet {
		return nil
	}

	// Calculate a_i
	aiElement := t.aPoly.Evaluate(root)

	// Calculate e_i
	eiElement := t.ePoly.Evaluate(root)

	// Calculate s_i
	siElement := t.sPoly.Evaluate(root)

	// Calculate delta_0i based on the signer set

	lagrangeCoeff := helper.Get0LagrangeCoefficientSetFr(signerSet)

	deltaShareAll := bls12381.NewFr().Zero()
	delta0ShareOwn := bls12381.NewFr().Zero()

	deltaShareFwd := bls12381.NewFr().Zero()

	indI := 0

	for indJ, signer := range signerSet {
		if signer != t.ownIndex {
			// cij * Lj, i = t.ownIndex
			deltaShareFwd.Mul(t.delta0Poly[signer][forwardDirection].Evaluate(root), lagrangeCoeff[indJ])
			// cji * Li, i = t.ownIndex
			delta0ShareOwn.Add(delta0ShareOwn, t.delta0Poly[signer][backwardDirection].Evaluate(root))

		} else {
			indI = indJ
		}

	}

	// continue with ownIndex calculation,
	// second term with Li coefficient

	delta0ShareOwn.Mul(lagrangeCoeff[signerSet[indI]], delta0ShareOwn)
	deltaShareAll.Add(delta0ShareOwn, deltaShareFwd)

	// delta0 calculation finished

	delta0i := poly.NewEmpty() //TODO: for all i <= N

	for _, signer := range signerSet {
		if signer != t.ownIndex {
			delta0i.Add(t.delta0Poly[signer][forwardDirection])
			delta0i.Add(t.delta0Poly[signer][backwardDirection])
		}
	}
	delta0i.Add(t.usk)

	// Calculate alpha_i based on the signer set
	alphai := poly.NewEmpty()
	for _, signer := range signerSet {
		if signer != t.ownIndex {
			alphai.Add(t.alphaPoly[signer])
		}
	}
	alphai.Add(t.uk)
	alphaiElement := alphai.Evaluate(root)

	// Calculate delta_1i based on the signer set
	delta1i := poly.NewEmpty()
	for _, signer := range signerSet {
		if signer != t.ownIndex {
			delta1i.Add(t.delta1Poly[signer])
		}
	}
	delta1i.Add(t.uv)

	deltaiPolyLagr := poly.NewEmpty()
	deltaiPolyLagr.Add(delta1i)
	deltaiLagrElement := deltaiPolyLagr.Evaluate(root)

	deltaiLagrElement.Add(deltaiLagrElement, deltaShareAll)

	return NewBBSPlusTuple(t.skShare, aiElement, eiElement, siElement, alphaiElement, deltaiLagrElement)
}

// BBSPlusTuple is a share of a pre-computed BBS+ signature generated by the EvalCombined function of the PCG.
type BBSPlusTuple struct {
	SkShare    *bls12381.Fr
	AShare     *bls12381.Fr
	EShare     *bls12381.Fr
	SShare     *bls12381.Fr
	AlphaShare *bls12381.Fr
	DeltaShare *bls12381.Fr
}

// EmptyTuple returns an empty BBSPlusTuple.
// The amount of AeTerms, SeTerms and AskTerms is determined by s.
func NewBBSPlusTuple(SkShare, AShare, EShare, SShare, AlphaShare, DeltaShare *bls12381.Fr) *BBSPlusTuple {
	tuple := &BBSPlusTuple{
		SkShare:    bls12381.NewFr(),
		AShare:     bls12381.NewFr(),
		EShare:     bls12381.NewFr(),
		SShare:     bls12381.NewFr(),
		AlphaShare: bls12381.NewFr(),
		DeltaShare: bls12381.NewFr(),
	}
	// Copy the values of the parameters into the tuple
	tuple.SkShare.FromBytes(SkShare.ToBytes())
	tuple.AShare.FromBytes(AShare.ToBytes())
	tuple.EShare.FromBytes(EShare.ToBytes())
	tuple.SShare.FromBytes(SShare.ToBytes())
	tuple.AlphaShare.FromBytes(AlphaShare.ToBytes())
	tuple.DeltaShare.FromBytes(DeltaShare.ToBytes())
	return tuple
}

// Serialize converts a BBSPlusTuple into a byte slice.
func (t *BBSPlusTuple) Serialize() ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)

	// serialize each field of BBSPlusTuple
	if err := encoder.Encode(t.SkShare.ToBytes()); err != nil {
		return nil, err
	}

	if err := encoder.Encode(t.AShare.ToBytes()); err != nil {
		return nil, err
	}

	if err := encoder.Encode(t.EShare.ToBytes()); err != nil {
		return nil, err
	}

	if err := encoder.Encode(t.SShare.ToBytes()); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Deserialize converts a byte slice into a BBSPlusTuple.
func (t *BBSPlusTuple) Deserialize(data []byte) error {
	b := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(b)

	// Deserialize skShare, AShare, EShare, SShare
	var skShareBytes, aShareBytes, eShareBytes, sShareBytes []byte
	if err := decoder.Decode(&skShareBytes); err != nil {
		return err
	}
	t.SkShare.FromBytes(skShareBytes)

	if err := decoder.Decode(&aShareBytes); err != nil {
		return err
	}
	t.AShare.FromBytes(aShareBytes)

	if err := decoder.Decode(&eShareBytes); err != nil {
		return err
	}
	t.EShare.FromBytes(eShareBytes)

	if err := decoder.Decode(&sShareBytes); err != nil {
		return err
	}
	t.SShare.FromBytes(sShareBytes)

	return nil
}
