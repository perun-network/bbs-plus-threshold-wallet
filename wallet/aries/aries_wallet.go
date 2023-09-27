package aries_wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	aries_wallet "github.com/hyperledger/aries-framework-go/pkg/wallet"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/wallet"
	"golang.org/x/exp/slices"
)

const (
	externalPrefix = "http://"

	walletExpiry = 10 * time.Minute
)

type AriesWallet struct {
	alias     string
	secretKey []byte
	PublicKey []byte

	aries           *aries.Aries
	vcwallet        *vcwallet.Client
	walletIsExpired bool

	collectionIDs []string
}

func (a *AriesWallet) GetAlias() string {
	return a.alias
}

func NewAriesWallet(alias, endpoint string, secretKey []byte) (*AriesWallet, error) {
	a := &AriesWallet{}
	a.alias = alias
	a.secretKey = secretKey

	inbound, err := http.NewInbound(endpoint, externalPrefix+endpoint, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create inbound transport for %s: %w", alias, err)
	}

	a.aries, err = aries.New(aries.WithInboundTransport(inbound))
	if err != nil {
		return nil, fmt.Errorf("failed to create framework for %s: %w", alias, err)
	}

	ctx, err := a.aries.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to get context for %s: %w", alias, err)
	}

	// Create User Wallet profile and wallet
	err = vcwallet.CreateProfile(alias, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet profile for %s: %w", alias, err)
	}
	a.vcwallet, err = vcwallet.New(alias, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create new vcwallet for %s: %w", alias, err)
	}

	// Open wallet
	err = a.vcwallet.Open(
		aries_wallet.WithUnlockExpiry(walletExpiry))
	if err != nil {
		return nil, fmt.Errorf("cannot open wallet for %s: %w", alias, err)
	}
	a.walletIsExpired = false

	go a.watchWalletExpiry()

	return a, nil
}

func (a *AriesWallet) Open() error {
	if a.aries == nil {
		return errors.New("aries is not initialised")
	}
	if a.vcwallet == nil {
		return errors.New("vcwallet is not initialised")
	}
	if !a.walletIsExpired {
		return errors.New("vcwallet is already open")
	}
	err := a.vcwallet.Open(
		aries_wallet.WithUnlockByPassphrase(string(a.secretKey)),
		aries_wallet.WithUnlockExpiry(walletExpiry))
	if err != nil {
		return fmt.Errorf("cannot open wallet for %s: %w", a.alias, err)
	}
	a.walletIsExpired = false

	a.watchWalletExpiry()
	return nil
}

func (a *AriesWallet) Close() error {
	var err error
	if a.vcwallet != nil {
		a.vcwallet.Close()
		a.walletIsExpired = true
	}
	if a.aries != nil {
		err = a.aries.Close()
	}
	if err != nil {
		return fmt.Errorf("close Aries framework: %w", err)
	}
	return nil

}

func (a *AriesWallet) Store(document *wallet.Document) error {
	if a.aries == nil {
		return errors.New("aries is not initialised")
	}
	if a.vcwallet == nil {
		return errors.New("vcwallet is not initialised")
	}
	if a.walletIsExpired {
		return errors.New("vcwallet had expired")
	}
	if !slices.Contains(a.collectionIDs, document.CollectionID) {
		collection := newCollection(document.CollectionID, a.alias)
		collectionBytes, err := json.Marshal(collection)
		if err != nil {
			return fmt.Errorf("marshal collection: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Collection, collectionBytes)
		if err != nil {
			return fmt.Errorf("add a new collection to wallet: %w", err)
		}
		a.collectionIDs = append(a.collectionIDs, collection.ID)
	}
	switch document.Type {
	case wallet.Credential:
		cred, err := newCredential(document)
		if err != nil {
			return fmt.Errorf("create aries credential: %w", err)
		}
		credBytes, err := cred.MarshalJSON()
		if err != nil {
			return fmt.Errorf("marshal credential: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Credential,
			credBytes,
			aries_wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add new credential to wallet: %w", err)
		}
	case wallet.Signature:
		sig, err := newSignature(document)
		if err != nil {
			return fmt.Errorf("create aries signature: %w", err)
		}
		sigBytes, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("marshal signature: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Metadata,
			sigBytes,
			aries_wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add signature to collection: %w", err)
		}
	case wallet.Presignature:
		preSig, err := newPresignature(document)
		if err != nil {
			return fmt.Errorf("create aries presignature: %w", err)
		}
		preSigBytes, err := json.Marshal(preSig)
		if err != nil {
			return fmt.Errorf("marshal presignature: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Metadata,
			[]byte(string(preSigBytes)),
			aries_wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add presignature to collection: %w", err)
		}
	case wallet.PartialSignature:
		partialSig, err := newPartialSignature(document)
		if err != nil {
			return fmt.Errorf("create aries partial signature: %w", err)
		}
		partialSigBytes, err := json.Marshal(partialSig)
		if err != nil {
			return fmt.Errorf("marshal partial signature: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Metadata,
			partialSigBytes,
			aries_wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add partial signature to collection: %w", err)
		}
	case wallet.PublicKey:
		publicKey, err := newPublicKey(document)
		if err != nil {
			return fmt.Errorf("create aries public key: %w", err)
		}
		publicKeyBytes, err := json.Marshal(publicKey)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Metadata,
			publicKeyBytes,
			aries_wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add public key to collection: %w", err)
		}
	case wallet.SecretKey:
		secretKey, err := newSecretKey(document)
		if err != nil {
			return fmt.Errorf("create aries secret key: %w", err)
		}
		secretKeyBytes, err := json.Marshal(secretKey)
		if err != nil {
			return fmt.Errorf("marshal secret key: %w", err)
		}
		err = a.vcwallet.Add(aries_wallet.Metadata,
			secretKeyBytes,
			aries_wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add secret key to collection: %w", err)
		}
	default:
		return errors.New("unknown document type")
	}
	return nil
}

func (a *AriesWallet) AddCollection(collectionID string) error {
	if a.aries == nil {
		return errors.New("aries is not initialised")
	}
	if a.vcwallet == nil {
		return errors.New("vcwallet is not initialised")
	}
	if a.walletIsExpired {
		return errors.New("vcwallet had expired")
	}
	if slices.Contains(a.collectionIDs, collectionID) {
		return fmt.Errorf("collection is already added")
	}
	collection := newCollection(collectionID, a.alias)
	collectionBytes, err := json.Marshal(collection)
	if err != nil {
		return fmt.Errorf("marshal collection: %w", err)
	}
	err = a.vcwallet.Add(aries_wallet.Collection, collectionBytes)
	if err != nil {
		return fmt.Errorf("add a new collection to wallet: %w", err)
	}
	a.collectionIDs = append(a.collectionIDs, collection.ID)
	return nil
}

func (a *AriesWallet) Get(contentType wallet.ContentType, documentID string) (*wallet.Document, error) {
	if a.aries == nil {
		return nil, errors.New("aries is not initialised")
	}
	if a.vcwallet == nil {
		return nil, errors.New("vcwallet is not initialised")
	}
	if a.walletIsExpired {
		return nil, errors.New("vcwallet had expired")
	}
	switch contentType {
	case wallet.Credential:
		for _, collectionID := range a.collectionIDs {
			credentials, err := a.vcwallet.GetAll(aries_wallet.Credential, aries_wallet.FilterByCollection(collectionID))
			if err != nil {
				return nil, fmt.Errorf("cannot get collection %s: %w", collectionID, err)
			}

			credentialRaw, ok := credentials[documentID]
			if ok {
				var credential verifiable.Credential
				err = json.Unmarshal(credentialRaw, &credential)
				if err != nil {
					return nil, fmt.Errorf("unmarshal raw credential: %w", err)
				}
				document, err := documentFromSubject(credential.Subject)
				if err != nil {
					return nil, fmt.Errorf("retrieve document from credential: %w", err)
				}
				if document.Type == wallet.Credential {
					return document, nil
				}
			}
		}
		return nil, errors.New("cannot get credential from wallet")
	case wallet.Signature:
		for _, collectionID := range a.collectionIDs {
			metadatas, err := a.vcwallet.GetAll(aries_wallet.Metadata, aries_wallet.FilterByCollection(collectionID))
			if err != nil {
				return nil, fmt.Errorf("cannot get collection %s: %w", collectionID, err)
			}
			metadataRaw, ok := metadatas[documentID]
			if ok {
				var metadata AriesMetaData
				err = json.Unmarshal(metadataRaw, &metadata)
				if err != nil {
					return nil, fmt.Errorf("unmarshal raw metatdata: %w", err)
				}
				document := metadata.Subject
				if metadata.Type == "signature" && document.Type == wallet.Signature {
					return document, nil
				}
			}
		}
		return nil, errors.New("cannot get signature from wallet")
	case wallet.Presignature:
		for _, collectionID := range a.collectionIDs {
			metadatas, err := a.vcwallet.GetAll(aries_wallet.Metadata, aries_wallet.FilterByCollection(collectionID))
			if err != nil {
				return nil, fmt.Errorf("cannot get collection %s: %w", collectionID, err)
			}
			metadataRaw, ok := metadatas[documentID]
			if ok {
				var metadata AriesMetaData
				err = json.Unmarshal(metadataRaw, &metadata)
				if err != nil {
					return nil, fmt.Errorf("unmarshal raw metadata: %w", err)
				}
				document := metadata.Subject
				if metadata.Type == "presignature" && document.Type == wallet.Presignature {
					return document, nil
				}
			}
		}
		return nil, errors.New("cannot get presignature from wallet")
	case wallet.PartialSignature:
		for _, collectionID := range a.collectionIDs {
			metadatas, err := a.vcwallet.GetAll(aries_wallet.Metadata, aries_wallet.FilterByCollection(collectionID))
			if err != nil {
				return nil, fmt.Errorf("cannot get collection %s: %w", collectionID, err)
			}
			metadataRaw, ok := metadatas[documentID]
			if ok {
				var metadata AriesMetaData
				err = json.Unmarshal(metadataRaw, &metadata)
				if err != nil {
					return nil, fmt.Errorf("unmarshal raw metadata: %w", err)
				}
				document := metadata.Subject
				if metadata.Type == "partial_signature" && document.Type == wallet.PartialSignature {
					return document, nil
				}
			}
		}
		return nil, errors.New("cannot get partial signature from wallet")
	case wallet.PublicKey:
		for _, collectionID := range a.collectionIDs {
			metadatas, err := a.vcwallet.GetAll(aries_wallet.Metadata, aries_wallet.FilterByCollection(collectionID))
			if err != nil {
				return nil, fmt.Errorf("cannot get collection %s: %w", collectionID, err)
			}
			metadataRaw, ok := metadatas[documentID]
			if ok {
				var metadata AriesMetaData
				err = json.Unmarshal(metadataRaw, &metadata)
				if err != nil {
					return nil, fmt.Errorf("unmarshal raw metadata: %w", err)
				}
				document := metadata.Subject
				if metadata.Type == "public_key" && document.Type == wallet.PublicKey {
					return document, nil
				}
			}
		}
		return nil, errors.New("cannot get public key from wallet")
	case wallet.SecretKey:
		for _, collectionID := range a.collectionIDs {
			metadatas, err := a.vcwallet.GetAll(aries_wallet.Metadata, aries_wallet.FilterByCollection(collectionID))
			if err != nil {
				return nil, fmt.Errorf("cannot get collection %s: %w", collectionID, err)
			}
			metadataRaw, ok := metadatas[documentID]
			if ok {
				var metadata AriesMetaData
				err = json.Unmarshal(metadataRaw, &metadata)
				if err != nil {
					return nil, fmt.Errorf("unmarshal raw metadata: %w", err)
				}
				document := metadata.Subject
				if err != nil {
					return nil, fmt.Errorf("retrieve document from metadata: %w", err)
				}
				if metadata.Type == "secret_key" && document.Type == wallet.SecretKey {
					return document, nil
				}
			}
		}
		return nil, errors.New("cannot get secret key from wallet")
	default:
		return nil, errors.New("unknown document type")
	}
}

func (a *AriesWallet) GetCollection(collectionID string) ([]*wallet.Document, error) {
	var collection []*wallet.Document
	credentials, err := a.vcwallet.GetAll(aries_wallet.Credential, aries_wallet.FilterByCollection(collectionID+collectionID))
	if err != nil {
		return nil, fmt.Errorf("get credentials with collection id %s: %w", collectionID, err)
	}
	for key, value := range credentials {
		var credential verifiable.Credential
		err := json.Unmarshal(value, &credential)
		if err != nil {
			return nil, fmt.Errorf("unmarshal credential %s: %w", key, err)
		}
		document, err := documentFromSubject(credential.Subject)
		if err != nil {
			return nil, fmt.Errorf("retrieve document from credential: %w", err)
		}
		collection = append(collection, document)
	}
	metadatas, err := a.vcwallet.GetAll(aries_wallet.Metadata, aries_wallet.FilterByCollection(collectionID))
	if err != nil {
		return nil, fmt.Errorf("get signatures with collection id %s: %w", collectionID, err)
	}
	for key, value := range metadatas {
		var metadata AriesMetaData
		err := json.Unmarshal(value, &metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal metadata %s: %w", key, err)
		}

		document := metadata.Subject
		collection = append(collection, document)
	}
	return collection, nil
}

func (a *AriesWallet) RemoveCollection(collectionID string) error {
	err := a.vcwallet.Remove(aries_wallet.Collection, collectionID)
	if err != nil {
		return fmt.Errorf("remove collection from wallet: %w", err)
	}
	return nil
}

func (a *AriesWallet) Remove(contentType wallet.ContentType, documentID string) error {
	switch contentType {
	case wallet.Credential:
		err := a.vcwallet.Remove(aries_wallet.Credential, documentID)
		if err != nil {
			return fmt.Errorf("remove credential from wallet: %w", err)
		}
		return nil
	case wallet.Signature:
		err := a.vcwallet.Remove(aries_wallet.Metadata, documentID)
		if err != nil {
			return fmt.Errorf("remove signature from wallet: %w", err)
		}
		return nil
	case wallet.Presignature:
		err := a.vcwallet.Remove(aries_wallet.Metadata, documentID)
		if err != nil {
			return fmt.Errorf("remove signature from wallet: %w", err)
		}
		return nil
	case wallet.PartialSignature:
		err := a.vcwallet.Remove(aries_wallet.Metadata, documentID)
		if err != nil {
			return fmt.Errorf("remove signature from wallet: %w", err)
		}
		return nil
	case wallet.PublicKey:
		err := a.vcwallet.Remove(aries_wallet.Metadata, documentID)
		if err != nil {
			return fmt.Errorf("remove signature from wallet: %w", err)
		}
		return nil
	case wallet.SecretKey:
		err := a.vcwallet.Remove(aries_wallet.Metadata, documentID)
		if err != nil {
			return fmt.Errorf("remove signature from wallet: %w", err)
		}
		return nil
	default:
		return errors.New("remove content type not supported")
	}
}

func (a *AriesWallet) VerifyThresholdSignature(credentials []*wallet.Document, signature *wallet.Document, publicKey *wallet.Document) (bool, error) {
	if credentials[0] == nil {
		return false, errors.New("empty credentials list")
	}
	var messages []*bls12381.Fr
	collectionID := credentials[0].CollectionID
	for _, credential := range credentials {
		if credential.Type != wallet.Credential {
			return false, errors.New("unsupported document type")
		}
		if collectionID != credential.CollectionID {
			return false, errors.New("unmatching collection ID")
		}
		message := bls12381.NewFr().FromBytes(credential.Content)
		messages = append(messages, message)
	}
	if signature.Type != wallet.Signature {
		return false, errors.New("type failed signature")
	}
	if publicKey.Type != wallet.PublicKey {
		return false, errors.New("type failed public key")
	}

	thresholdSig := fhks_bbs_plus.NewThresholdSignature()
	err := thresholdSig.FromBytes(signature.Content)
	if err != nil {
		return false, fmt.Errorf("decode threshold signature: %w", err)
	}

	pk := &fhks_bbs_plus.PublicKey{}
	err = pk.FromBytes(publicKey.Content)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}

	return thresholdSig.Verify(messages, pk), nil
}

func (a *AriesWallet) watchWalletExpiry() {

}
