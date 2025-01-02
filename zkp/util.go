package zkp

import (
	"encoding/binary"
	"errors"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
)

// MultiScalarMulVarTimeG1 performs multi-scalar multiplication on G1 points with corresponding scalars
func MultiScalarMulVarTimeG1(bases []*bls12381.PointG1, scalars []*bls12381.Fr) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	result := g1.Zero()

	for i := range bases {
		temp := g1.New()
		g1.MulScalar(temp, bases[i], scalars[i])
		g1.Add(result, result, temp)
	}

	return result
}

// ComputeB computes B = h0^s + sum(h_i^m_i) for a given signature scalar s and messages
func ComputeB(s *bls12381.Fr, messages []*SignatureMessage, key *fhks_bbs_plus.PublicKey) *bls12381.PointG1 {
	const basesOffset = 2

	// Create a commitment builder with an expected size (messages + offset)
	cb := NewCommitmentBuilder(len(messages) + basesOffset)

	// Add generator G1 (assumed to be g1.One() in this case)
	g1 := bls12381.NewG1()
	cb.Add(g1.One(), bls12381.NewFr().One()) // Add G^1

	// Add h0^s
	cb.Add(key.H0, s)

	// Add h_i^m_i for each message
	for i := 0; i < len(messages); i++ {
		cb.Add(key.H[i], messages[i].value)
	}

	// Build the final commitment by performing multi-scalar multiplication
	return cb.Build()
}

func IsPointZero(point *bls12381.PointG1) bool {
	g1 := bls12381.NewG1()
	return g1.IsZero(point)
}

func ProcessMessages(reqMessages [][]byte, revealedIndices []int, publicKeyLength int) ([]ProofMessage, map[int]struct{}, map[int]*SignatureMessage, error) {
	var messages []ProofMessage

	// Step 1: Validate and build the revealedSet from revealedIndices
	revealedSet := make(map[int]struct{})
	for _, r := range revealedIndices {
		if r >= publicKeyLength {
			return nil, nil, nil, fmt.Errorf("revealed value %d is out of bounds", r)
		}
		revealedSet[r] = struct{}{}
	}

	revealedMsgs := make(map[int]*SignatureMessage)

	// Iterate over revealed indices (zkptest.RevealedTest)

	// Step 2: Process each message and categorize it as revealed or hidden
	for i, msg := range reqMessages {
		msgFr := bls12381.NewFr().FromBytes(msg)
		frMsg := SignatureMessage{value: msgFr}

		if _, found := revealedSet[i]; found {
			messages = append(messages, ProofMessage{
				Revealed: &frMsg,
			})
			revealedMsgs[i] = &frMsg

		} else {
			messages = append(messages, ProofMessage{
				Hidden: &HiddenMessage{
					ProofSpecific: &ProofSpecificBlinding{
						Signature: &frMsg,
					},
				},
			})
		}
	}

	return messages, revealedSet, revealedMsgs, nil
}

func convertToFrArray(sigMessages []*SignatureMessage) []*bls12381.Fr {
	frArray := make([]*bls12381.Fr, len(sigMessages))
	for i, msg := range sigMessages {
		frArray[i] = msg.value
	}
	return frArray
}

func bitvectorToIndices(data []byte) []int {
	revealedIndices := make([]int, 0)
	scalar := 0

	for _, v := range data {
		remaining := 8

		for v > 0 {
			revealed := v & 1
			if revealed == 1 {
				revealedIndices = append(revealedIndices, scalar)
			}

			v >>= 1
			scalar++
			remaining--
		}

		scalar += remaining
	}

	return revealedIndices
}

type PokPayload struct {
	messagesCount int
	revealed      []int
}

func (p *PokPayload) GetRevealed() []int {
	return p.revealed
}

func uint16FromBytes(bytes []byte) uint16 {
	return binary.BigEndian.Uint16(bytes)
}

func uint32FromBytes(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

// nolint:gomnd
func ParsePoKPayload(bytes []byte) (*PokPayload, error) {
	if len(bytes) < 2 {
		return nil, errors.New("invalid size of PoK payload len(bytes) < 2")
	}

	messagesCount := int(uint16FromBytes(bytes[0:2]))
	offset := lenInBytes(messagesCount)

	if len(bytes) < offset {
		return nil, errors.New("invalid size of PoK payload < offset")
	}

	revealed := bitvectorToIndices(reverseBytes(bytes[2:offset]))

	return &PokPayload{
		messagesCount: messagesCount,
		revealed:      revealed,
	}, nil
}

func (p *PokPayload) ToBytes() ([]byte, error) {
	bytes := make([]byte, p.LenInBytes())

	binary.BigEndian.PutUint16(bytes, uint16(p.messagesCount))

	bitvector := bytes[2:]

	for _, r := range p.revealed {
		idx := r / 8
		bit := r % 8

		if len(bitvector) <= idx {
			return nil, errors.New("invalid size of PoK payload")
		}

		bitvector[idx] |= 1 << bit
	}

	reverseBytes(bitvector)

	return bytes, nil
}

func (p *PokPayload) LenInBytes() int {
	return lenInBytes(p.messagesCount)
}

func lenInBytes(messagesCount int) int {
	return 2 + (messagesCount / 8) + 1
}

func NewPoKPayload(messagesCount int, revealed []int) *PokPayload {
	return &PokPayload{
		messagesCount: messagesCount,
		revealed:      revealed,
	}
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

func ExtractSignatureMessages(messages []ProofMessage) []*SignatureMessage {
	sigMessages := make([]*SignatureMessage, len(messages))

	for i, m := range messages {
		if m.Revealed != nil {
			sigMessages[i] = m.Revealed
		} else if m.Hidden != nil && m.Hidden.ProofSpecific != nil {
			sigMessages[i] = m.Hidden.ProofSpecific.Signature
		} else if m.Hidden != nil && m.Hidden.External != nil {
			sigMessages[i] = m.Hidden.External.Signature
		}
	}

	return sigMessages
}

func BitvectorToRevealed(data []byte) map[int]struct{} {
	revealedMessages := make(map[int]struct{})
	scalar := 0

	// Iterate over the byte slice in reverse (big-endian interpretation)
	for i := len(data) - 1; i >= 0; i-- {
		v := data[i]   // Get the current byte
		remaining := 8 // Track remaining bits in the byte

		// Process each bit in the byte
		for v > 0 {
			revealed := v & 1 // Check if the least significant bit is set
			if revealed == 1 {
				revealedMessages[scalar] = struct{}{} // Add index to revealed set
			}
			v >>= 1     // Shift right to process the next bit
			scalar++    // Increment scalar to track bit position
			remaining-- // Decrease remaining bits count
		}
		scalar += remaining // Skip any remaining bits that are 0
	}

	return revealedMessages
}
