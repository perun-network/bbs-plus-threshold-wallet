package zkp

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"golang.org/x/crypto/blake2b"
)

func HashToFr(data []byte) *bls12381.Fr {
	// Create a new BLAKE2b hash with the desired output size
	hasher, err := blake2b.New(helper.LenBytesFr, nil)
	if err != nil {
		panic(err)
	}

	// Write data to the hasher
	hasher.Write(data)

	// Get the hash result
	res := hasher.Sum(nil)

	// Convert the hash result to an Fr element
	fr := &bls12381.Fr{}
	fr.FromBytes(res)

	return fr
}

func HashMessagesToFr(msgs [][]byte) []*bls12381.Fr {
	frMsgs := make([]*bls12381.Fr, len(msgs))

	for i, msg := range msgs {
		frMsgs[i] = HashToFr(msg)
	}

	return frMsgs
}

func ByteMsgToFr(msgs [][]byte) []*bls12381.Fr {
	frMsgs := make([]*bls12381.Fr, len(msgs))

	for i, msg := range msgs {
		frMsgs[i] = bls12381.NewFr().FromBytes(msg)
	}

	return frMsgs
}

func FrToSigMessages(messages [][]byte) []*SignatureMessage {
	messagesFr := make([]*SignatureMessage, len(messages))

	for i := range messages {
		messagesFr[i] = &SignatureMessage{
			value: bls12381.NewFr().FromBytes(messages[i]),
		}
	}

	return messagesFr
}
