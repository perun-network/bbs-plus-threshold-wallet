package wallet

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/uuid"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation"
)

type ThresholdWallet struct {
	ID           string
	mainWallet   Wallet
	partyWallets []*PartyWallet
	threshold    int
}

func NewThresholdWallet(mainWallet Wallet) *ThresholdWallet {
	partyWallets := make([]*PartyWallet, 0)
	return &ThresholdWallet{
		ID:           "did:main:" + uuid.New().URN(),
		mainWallet:   mainWallet,
		partyWallets: partyWallets,
		threshold:    0,
	}
}

func (tw *ThresholdWallet) Close() error {
	for id, party := range tw.partyWallets {
		err := party.Close()
		if err != nil {
			return fmt.Errorf("closing party wallet %d: %w", id, err)
		}
	}
	err := tw.mainWallet.Close()
	if err != nil {
		return fmt.Errorf("closing main wallet: %w", err)
	}
	return nil
}

func (tw *ThresholdWallet) Store(document *Document) error {
	return tw.mainWallet.Store(document)
}

func (tw *ThresholdWallet) Get(contentType ContentType, documentID string) (*Document, error) {
	return tw.mainWallet.Get(contentType, documentID)
}

func (tw *ThresholdWallet) GetCollection(collectionID string) ([]*Document, error) {
	return tw.mainWallet.GetCollection(collectionID)
}

func (tw *ThresholdWallet) Remove(contentType ContentType, documentID string) error {
	return tw.mainWallet.Remove(contentType, documentID)
}

func (tw *ThresholdWallet) RemoveCollection(collectionID string) error {
	return tw.mainWallet.RemoveCollection(collectionID)
}

func (tw *ThresholdWallet) AddParticipant(partyWallet *PartyWallet) error {
	if partyWallet == nil {
		return errors.New("empty participant wallet")
	}
	for _, participant := range tw.partyWallets {
		if participant.ID == partyWallet.ID {
			return errors.New("party wallet is already added")
		}
	}
	tw.partyWallets = append(tw.partyWallets, partyWallet)
	return nil
}

func (tw *ThresholdWallet) RemoveParticipant(participantID string) error {
	var newParticipants []*PartyWallet

	for _, wallet := range tw.partyWallets {
		if wallet.ID != participantID {
			newParticipants = append(newParticipants, wallet)
		}
	}

	if len(newParticipants) == len(tw.partyWallets) {
		return fmt.Errorf("party wallet with ID %s not found", participantID)
	}

	tw.partyWallets = newParticipants
	return nil
}

func (tw *ThresholdWallet) UpdateThreshold(threshold int) error {
	if len(tw.partyWallets) < threshold {
		return errors.New("threshold out of bound")
	}
	tw.threshold = threshold
	return nil
}

func (tw *ThresholdWallet) GeneratePrecomputation(messagesCount int) (*Document, string, error) {
	var seed [16]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, "", fmt.Errorf("generate random seed: %w", err)
	}
	sk, precomputation := precomputation.GeneratePPPrecomputation(seed, tw.threshold, messagesCount, len(tw.partyWallets))
	collectionID := fmt.Sprintf(CollectionIDTemplate, uuid.New())
	secretKeyDoc := NewDocument(SecretKey, sk.ToBytes(), collectionID, tw.ID)
	tw.mainWallet.Store(secretKeyDoc)

	publicKeyDoc, err := tw.generatePublicKey(secretKeyDoc, messagesCount)
	if err != nil {
		return nil, "", fmt.Errorf("generate public key: %w", err)
	}

	for idx, perPartyPrecomputation := range precomputation {
		preSigByte, err := perPartyPrecomputation.PreSignatures[0].ToBytes()
		if err != nil {
			return nil, "", fmt.Errorf("encode per party presignature: %w", err)
		}
		preSignatureDoc := NewDocument(Presignature, preSigByte, collectionID, tw.ID)
		err = tw.partyWallets[idx].Store(preSignatureDoc)
		if err != nil {
			return nil, "", fmt.Errorf("store presignature in party wallet %d: %w", idx, err)
		}
		err = tw.partyWallets[idx].Store(publicKeyDoc)
		if err != nil {
			return nil, "", fmt.Errorf("store public key in party wallet %d: %w", idx, err)
		}
	}
	return publicKeyDoc, collectionID, nil
}

func (tw *ThresholdWallet) SignThresholdSignature(documents []*Document, indices []int) (*Document, error) {
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

	if len(indices) < tw.threshold {
		return nil, errors.New("not enough pariticipants to produce a signature")
	}
	_, err := tw.GetCollection(collectionID)
	if err != nil {
		return nil, fmt.Errorf("no corresponding collection from wallet: %w", err)
	}

	var partialSigs []*Document
	for iT := 0; iT < tw.threshold; iT++ {
		if indices[iT] > len(tw.partyWallets) {
			return nil, errors.New("participant index out of bound")
		}
		party := tw.partyWallets[indices[iT]-1]
		partialSig, err := party.CreatePartialSignature(documents, indices[iT], indices)
		if err != nil {
			return nil, fmt.Errorf("generate partial signature from party %d: %w", indices[iT]-1, err)
		}
		partialSigs = append(partialSigs, partialSig)
	}

	signature, err := tw.combinePartialSignatures(partialSigs)
	if err != nil {
		return nil, fmt.Errorf("create signature from partials: %w", err)
	}

	if err != nil {
		return nil, fmt.Errorf("store signature in wallet: %w", err)
	}
	return signature, nil
}

func (tw *ThresholdWallet) VerifyThresholdSignature(credentials []*Document, signature *Document, publicKey *Document) (bool, error) {
	return tw.mainWallet.VerifyThresholdSignature(credentials, signature, publicKey)
}

func (tw *ThresholdWallet) generatePublicKey(secretKey *Document, messageCount int) (*Document, error) {
	var seed [16]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf("generate random seed: %w", err)
	}
	sk := bls12381.NewFr().FromBytes(secretKey.Content)
	publicKey := fhks_bbs_plus.GeneratePublicKey(seed, sk, messageCount)
	pkByte, err := publicKey.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	publicKeyDoc := NewDocument(PublicKey, pkByte, secretKey.CollectionID, tw.ID)
	return publicKeyDoc, nil
}

func (tw *ThresholdWallet) combinePartialSignatures(partialSigs []*Document) (*Document, error) {
	if len(partialSigs) != tw.threshold {
		return nil, errors.New("incorrect number of partial signatures")
	}
	collectionID := partialSigs[0].CollectionID
	partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, tw.threshold)
	for id, partialSig := range partialSigs {
		if collectionID != partialSig.CollectionID {
			return nil, errors.New("incorrect collection ID")
		}
		partialSignature := fhks_bbs_plus.NewPartialThresholdSignature()
		err := partialSignature.FromBytes(partialSig.Content)
		if err != nil {
			return nil, fmt.Errorf("decode partial signature: %w", err)
		}
		partialSignatures[id] = partialSignature
	}
	signature := fhks_bbs_plus.NewThresholdSignature().FromPartialSignatures(partialSignatures)
	sigByte, err := signature.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("encode threshold signature: %w", err)
	}
	thesholdSignatureDoc := NewDocument(Signature, sigByte, collectionID, tw.ID)
	return thesholdSignatureDoc, nil
}
