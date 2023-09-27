package wallet

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
)

type PartyWallet struct {
	ID     string // Unique identifier of the party.
	wallet Wallet
}

func NewPartyWallet(wallet Wallet) *PartyWallet {
	return &PartyWallet{
		ID:     "did:party:" + uuid.New().URN(),
		wallet: wallet,
	}
}

func (p *PartyWallet) Open() error {
	return p.wallet.Open()
}

func (p *PartyWallet) Close() error {
	return p.wallet.Close()
}

func (p *PartyWallet) Store(document *Document) error {
	return p.wallet.Store(document)
}

func (p *PartyWallet) Get(contentType ContentType, documentID string) (*Document, error) {
	return p.wallet.Get(contentType, documentID)
}

func (p *PartyWallet) GetCollection(collectionID string) ([]*Document, error) {
	return p.wallet.GetCollection(collectionID)
}

func (p *PartyWallet) Remove(contentType ContentType, documentID string) error {
	return p.wallet.Remove(contentType, documentID)
}

func (p *PartyWallet) RemoveCollection(collectionID string) error {
	return p.wallet.RemoveCollection(collectionID)
}

func (p *PartyWallet) CreatePartialSignature(documents []*Document, ownIndex int, indices []int) (*Document, error) {
	if len(documents) == 0 {
		return nil, errors.New("empty credential list")
	}
	collectionID := documents[0].CollectionID
	for _, credential := range documents {
		if credential.Type != Credential {
			return nil, errors.New("unsupported document type")
		}
		if collectionID != credential.CollectionID {
			return nil, errors.New("unmatching collection ID")
		}
	}

	collection, err := p.wallet.GetCollection(collectionID)
	if err != nil {
		return nil, fmt.Errorf("collection not found for this document: %w", err)
	}

	publicKey := &fhks_bbs_plus.PublicKey{}
	for _, value := range collection {
		if value.Type == PublicKey {
			err = publicKey.FromBytes(value.Content)
			if err != nil {
				return nil, fmt.Errorf("decode public key: %w", err)
			}
		}
	}

	for _, value := range collection {
		if value.Type == Presignature {
			preSignature := &fhks_bbs_plus.PerPartyPreSignature{}
			err := preSignature.FromBytes(value.Content)
			if err != nil {
				return nil, fmt.Errorf("decode presignature from wallet: %w", err)
			}

			partialSignature, err := generatePartialThresholdSignature(documents, publicKey, preSignature, ownIndex, indices)
			if err != nil {
				return nil, fmt.Errorf("generate partial signature from presignature: %w", err)
			}

			partialSigData, err := partialSignature.ToBytes()
			if err != nil {
				return nil, fmt.Errorf("encode partial signature: %w", err)
			}

			partialSigDocument := NewDocument(PartialSignature, partialSigData, collectionID, p.ID)
			if err := p.Store(partialSigDocument); err != nil {
				return nil, fmt.Errorf("store partial signature in wallet: %w", err)
			}
			return partialSigDocument, nil
		}
	}
	return nil, errors.New("presignature not found")
}

func (p *PartyWallet) Verify(credentials []*Document, signature *Document, publicKey *Document) (bool, error) {
	return p.wallet.VerifyThresholdSignature(credentials, signature, publicKey)
}

func generatePartialThresholdSignature(credentials []*Document,
	pk *fhks_bbs_plus.PublicKey,
	preSignature *fhks_bbs_plus.PerPartyPreSignature,
	ownIndex int,
	indices []int) (*fhks_bbs_plus.PartialThresholdSignature, error) {

	if len(credentials) == 0 {
		return nil, errors.New("empty credential list")
	}
	var messages []*bls12381.Fr
	collectionID := credentials[0].CollectionID
	for _, credential := range credentials {
		if credential.Type != Credential {
			return nil, errors.New("unsupported document type")
		}
		if collectionID != credential.CollectionID {
			return nil, errors.New("unmatching collection ID")
		}
		message := bls12381.NewFr().FromBytes(credential.Content)
		messages = append(messages, message)
	}

	partialSignature := fhks_bbs_plus.NewPartialThresholdSignature()
	partialSignature = partialSignature.New(messages, pk,
		fhks_bbs_plus.NewLivePreSignature().FromPreSignature(
			ownIndex, indices, preSignature))
	return partialSignature, nil
}
