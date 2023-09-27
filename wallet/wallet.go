package wallet

import "github.com/google/uuid"

// ContentType is the document content type.
type ContentType string

const (
	Credential       ContentType = "credential"
	Signature        ContentType = "signature"
	Presignature     ContentType = "presignature"
	PartialSignature ContentType = "partial_signature"
	SecretKey        ContentType = "secret_key"
	PublicKey        ContentType = "public_key"

	// ID templates
	CollectionIDTemplate       string = "did:collection:%s"
	CredentialIDTemplate       string = "did:credential:%s"
	SignatureIDTemplate        string = "did:signature:%s"
	PresignatureIDTemplate     string = "did:presignature:%s"
	PartialsignatureIDTemplate string = "did:partialsignature:%s"
	SecretkeyIDTemplate        string = "did:secretkey:%s"
	PublickeyIDTemplate        string = "did:publickey:%s"
)

type Document struct {
	ID           string      `json:"id"`           // Unique Identifier for the document.
	Type         ContentType `json:"type"`         // Type of the document.
	Content      []byte      `json:"content"`      // The content of the document.
	CollectionID string      `json:"collectionID"` // Identifier for linking documents.
	Author       string      `json:"author"`       // Original generator of the document.
}

func NewDocument(
	contentType ContentType,
	content []byte,
	collectionID string,
	author string) *Document {
	return &Document{
		ID:           uuid.New().URN(),
		Type:         contentType,
		Content:      content,
		CollectionID: collectionID,
		Author:       author,
	}
}

type Wallet interface {
	// Open opens makes the wallet's services available.
	Open() error

	// Close shutdowns the wallet's services.
	Close() error

	// Store adds a new document to wallet.
	Store(document *Document) error

	// AddCollection adds a new collection to wallet.
	AddCollection(collectionID string) error

	// Get retrieves a document from the wallet based on its content type and ID.
	Get(contentType ContentType, documentID string) (*Document, error)

	// GetCollection retrieves all documents from a collection based on the collectionID.
	GetCollection(collectionID string) ([]*Document, error)

	// Remove removes a document from the wallet based on its ID.
	Remove(contentType ContentType, documentID string) error

	// RemoveCollection removes an entire collection from the wallet.
	RemoveCollection(collectionID string) error

	// VerifyThresholdSignature verifies the signature of the credential with the provided public key.
	VerifyThresholdSignature(credentials []*Document, signature *Document, publicKey *Document) (bool, error)
}
