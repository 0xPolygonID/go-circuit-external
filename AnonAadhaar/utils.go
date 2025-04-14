package anonaadhaar

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/0xPolygonID/go-circuit-external/common"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// golang implementation of the splitToWords from AnonAadhaar utils
// https://github.com/anon-aadhaar/anon-aadhaar/blob/e0cbde3d8e4a3969a6e44a2999ec539439e61d58/packages/core/src/utils.ts#L21
func splitToWords(number, wordsize, numberElement *big.Int) ([]*big.Int, error) {
	t := new(big.Int).Set(number)
	words := []*big.Int{}

	power := new(big.Int).Exp(big.NewInt(2), wordsize, nil)
	for i := big.NewInt(0); i.Cmp(numberElement) < 0; i.Add(i, big.NewInt(1)) {
		mod := new(big.Int).Mod(t, power)
		words = append(words, mod)
		t.Div(t, power)
	}

	if t.Cmp(big.NewInt(0)) != 0 {
		return nil, fmt.Errorf("number %s does not fit in %d bits", number.String(), new(big.Int).Mul(wordsize, numberElement).Uint64())
	}

	return words, nil
}

// convert a PEM encoded key to a JWK
func pemToJWK(content []byte) (jwk.Key, error) {
	key, _, err := jwk.NewPEMDecoder().Decode(content)
	if err != nil {
		return nil, err
	}
	return jwk.Import(key)
}

func extractNfromPubKey(content []byte) (*big.Int, error) {
	key, err := pemToJWK(content)
	if err != nil {
		return nil, err
	}
	var n []byte
	if err := key.Get("n", &n); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(n), nil
}

// golang implementation of sha256Pad from zk-email helpers
// https://github.com/zkemail/zk-email-verify/blob/e1084969fbee16317290e4380b3837af74fea616/packages/helpers/src/sha-utils.ts#L88
func sha256Pad(m []byte, maxShaBytes int) (paddedMessage []byte, messageLen int, err error) {
	// do not modify the original message
	message := make([]byte, len(m))
	copy(message, m)

	msgLen := len(message) * 8
	msgLenBytes := common.Int64ToBytes(int64(msgLen))

	paddedMessage = append(message, 0x80)
	for ((len(paddedMessage)*8 + len(msgLenBytes)*8) % 512) != 0 {
		paddedMessage = append(paddedMessage, 0x00)
	}

	paddedMessage = append(paddedMessage, msgLenBytes...)
	if len(paddedMessage)*8%512 != 0 {
		return nil, 0, errors.New("padding did not complete properly")
	}

	messageLen = len(paddedMessage)
	for len(paddedMessage) < maxShaBytes {
		paddedMessage = append(paddedMessage, common.Int64ToBytes(0)...)
	}
	if len(paddedMessage) != maxShaBytes {
		return nil, 0, fmt.Errorf("padding to max length did not complete properly: got %d, expected %d", len(paddedMessage), maxShaBytes)
	}

	return paddedMessage, messageLen, nil
}
