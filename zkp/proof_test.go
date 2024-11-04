package zkp_test

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPoKOfSignatureProof(t *testing.T) {
	g1 := bls12381.NewG1()

	pubKey := fhks_bbs_plus.PublicKey{
		H:  []*bls12381.PointG1{g1.One(), g1.One()}, // Simplified example
		H0: g1.One(),
	}

	signature := fhks_bbs_plus.ThresholdSignature{
		CapitalA: g1.One(),
		E:        bls12381.NewFr().One(),
		S:        bls12381.NewFr().One(),
	}

	messages := []zkp.ProofMessage{
		{
			Revealed: func() *zkp.SignatureMessage {
				msg := &zkp.SignatureMessage{}
				msg.Set(bls12381.NewFr().One())
				return msg
			}(),
		},
		{
			Hidden: &zkp.HiddenMessage{
				ProofSpecific: &zkp.ProofSpecificBlinding{
					Signature: func() zkp.SignatureMessage {
						msg := zkp.SignatureMessage{}
						msg.Set(bls12381.NewFr().One())
						return msg
					}(),
				},
			},
		},
	}

	proof, err := zkp.NewPoKOfSignatureProof(signature, pubKey, messages)

	assert.NoError(t, err, "NewPoKOfSignatureProof should not return an error")
	assert.NotNil(t, proof, "NewPoKOfSignatureProof should return a valid proof")
}
