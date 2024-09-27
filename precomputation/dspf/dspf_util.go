package dspf

import (
	"errors"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation/dpf"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation/dpf/optreedpf"
)

// CreateKeyFromTypeID is a helper function that instantiates a DPF key based on the typeID.
func CreateKeyFromTypeID(typeID dpf.KeyType) (dpf.Key, error) {
	switch typeID {
	case dpf.OpTreeDPFKeyID:
		return optreedpf.EmptyKey(), nil
	// Add cases for other key types here
	default:
		return nil, errors.New("unknown key type")
	}
}
