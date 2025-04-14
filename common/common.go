package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/merklize"
)

func ConvertSiblings(siblings [][]*big.Int) [][]string {
	out := make([][]string, len(siblings))
	for i := range siblings {
		out[i] = make([]string, len(siblings[i]))
		out[i] = BigIntListToStrings(siblings[i])
	}
	return out
}

func HashValue(v interface{}) (*big.Int, error) {
	mv, err := merklize.NewValue(merklize.PoseidonHasher{}, v)
	if err != nil {
		return nil, fmt.Errorf("failed to create init merklizer: %w", err)
	}
	bv, err := mv.MtEntry()
	if err != nil {
		return nil, fmt.Errorf("failed to create merklize entry: %w", err)
	}
	return bv, nil
}

func DIDToID(did string) (core.ID, error) {
	d, err := w3c.ParseDID(did)
	if err != nil {
		return core.ID{}, fmt.Errorf("failed to parse did: %w", err)
	}
	id, err := core.IDFromDID(*d)
	if err != nil {
		return core.ID{}, fmt.Errorf("failed to convert did to id: %w", err)
	}
	return id, nil
}

func TimeToInt(t time.Time) int {
	return t.Year()*10000 + int(t.Month())*100 + t.Day()
}

func TimeToUnixNano(t time.Time) *big.Int {
	return new(big.Int).Mul(
		big.NewInt(t.Unix()),
		big.NewInt(1e9))
}

func BigIntListToStrings(b []*big.Int) []string {
	v := make([]string, len(b))
	for i := range b {
		v[i] = b[i].String()
	}
	return v
}

func Int64ToBytes(value int64) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, value)
	return buf.Bytes()
}

func Uint8ArrayToCharArray(a []uint8) []string {
	charArray := make([]string, len(a))
	for i, v := range a {
		charArray[i] = strconv.Itoa(int(v))
	}
	return charArray
}

func MustBigInt(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Sprintf("failed to parse big.Int: %s", s))
	}
	return i
}
