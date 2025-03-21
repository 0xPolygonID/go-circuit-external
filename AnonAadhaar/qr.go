package gocircuitexternal

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

const timeTemplate = "02-01-2006" // DD-MM-YYYY regarding to Indian format of date

type GenderString string

const (
	MaleString        GenderString = "M"
	FemaleString      GenderString = "F"
	TransgenderString GenderString = "T"
)

func (g GenderString) Int() GenderInt {
	switch g {
	case MaleString:
		return MaleInt
	case FemaleString:
		return FemaleInt
	case TransgenderString:
		return TransgenderInt
	}
	return 0
}

func IsValidGenderString(g GenderString) bool {
	switch g {
	case MaleString, FemaleString, TransgenderString:
		return true
	}
	return false
}

type GenderInt int

const (
	MaleInt        = 77 // M
	FemaleInt      = 70 // F
	TransgenderInt = 84 // T
)

func IsValidGenderInt(g GenderInt) bool {
	switch g {
	case MaleInt, FemaleInt, TransgenderInt:
		return true
	}
	return false
}

const (
	delimiter              = byte(255)
	ISTOffset              = 19800
	supportedQRDataVersion = "V2"
	halfYearSeconds        = 15776640
)

type Address struct {
	CareOf      string `json:"careOf"`
	District    string `json:"district"`
	Landmark    string `json:"landmark"`
	House       string `json:"house"`
	Location    string `json:"location"`
	PinCode     string `json:"pinCode"`
	PostOffice  string `json:"postOffice"`
	State       string `json:"state"`
	Street      string `json:"street"`
	SubDistrict string `json:"subDistrict"`
	VTC         string `json:"vtc"`
}

func (a *Address) String() string {
	const delimiter = " "
	return strings.Join([]string{
		a.CareOf,
		a.District,
		a.Landmark,
		a.House,
		a.Location,
		a.PinCode,
		a.PostOffice,
		a.State,
		a.Street,
		a.SubDistrict,
		a.VTC,
	}, delimiter)
}

// AnonAadhaarDataV2 is a struct that represents the data that is stored in Aadhaar QR code
// https://github.com/zkspecs/zkspecs/blob/main/specs/2/README.md
type AnonAadhaarDataV2 struct {
	Version            string    `json:"version"`
	ContactIndecator   string    `json:"contactIndicator"`
	ReferenceID        string    `json:"referenceID"`
	PassportLastDigits string    `json:"passportLastDigits"`
	SignedTime         time.Time `json:"signedTime"`
	Name               string    `json:"name"`
	DateOfBirth        string    `json:"dateOfBirth"`
	Gender             string    `json:"gender"`
	Address            Address   `json:"address"`
	MobileLastDigits   string    `json:"mobileLastDigits"`
	Photo              string    `json:"photo"`

	rawdata   []byte
	signature []byte
}

func createDecompressor(data []byte) (io.ReadCloser, error) {
	copied := make([]byte, len(data))
	if c := copy(copied, data); c != len(data) {
		return nil, fmt.Errorf("failed to copy data: %d", c)
	}
	zr, err := zlib.NewReader(bytes.NewReader(copied))
	if err != nil {
		return gzip.NewReader(bytes.NewReader(copied))
	}
	return zr, nil
}

// verify check formats
func (a *AnonAadhaarDataV2) verify() error {
	if a.SignedTime.IsZero() {
		return errors.New("signed time is not set")
	}
	_, err := time.Parse(timeTemplate, a.DateOfBirth) // DD-MM-YYYY check data format
	if err != nil {
		return fmt.Errorf("failed to parse date of birth '%s': %w", a.DateOfBirth, err)
	}
	if !IsValidGenderString(GenderString(a.Gender)) {
		return fmt.Errorf("invalid gender: '%s'", a.Gender)
	}
	if a.Address.PinCode == "" {
		return errors.New("pin code is empty")
	}
	if a.Address.State == "" {
		return errors.New("state is empty")
	}
	if len(a.signature) != 256 {
		return fmt.Errorf("signature length is not 256: %d", len(a.signature))
	}
	return nil
}

func (a *AnonAadhaarDataV2) UnmarshalQR(data *big.Int) error {
	r, err := createDecompressor(data.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create zlib/gzip reader: %w", err)
	}
	//nolint:errcheck // ignore error
	defer r.Close()
	uncompressedData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read compressed data: %w", err)
	}

	a.signature = uncompressedData[len(uncompressedData)-256:]

	// remove signature
	d := uncompressedData[:len(uncompressedData)-256]
	a.rawdata = d

	// remove photo part
	parts := bytes.Split(d, []byte{delimiter})
	partsWithoutPhoto := parts[:18]
	photo := parts[18:]

	a.Version = string(partsWithoutPhoto[0])
	a.ContactIndecator = string(partsWithoutPhoto[1])
	a.ReferenceID = string(partsWithoutPhoto[2])
	a.PassportLastDigits = string(partsWithoutPhoto[2][:4])
	sigtime, err := time.Parse("2006010215", string(partsWithoutPhoto[2][4:14])) // format: YYYYMMDDHH (24 hours representation)
	if err != nil {
		return fmt.Errorf("failed to parse signed time '%s': %w",
			string(partsWithoutPhoto[2][4:14]), err)
	}
	a.SignedTime = sigtime.Add(-ISTOffset * time.Second)
	a.Name = string(partsWithoutPhoto[3])
	a.DateOfBirth = string(partsWithoutPhoto[4])
	a.Gender = string(partsWithoutPhoto[5])
	a.Address = Address{
		CareOf:      string(partsWithoutPhoto[6]),
		District:    string(partsWithoutPhoto[7]),
		Landmark:    string(partsWithoutPhoto[8]),
		House:       string(partsWithoutPhoto[9]),
		Location:    string(partsWithoutPhoto[10]),
		PinCode:     string(partsWithoutPhoto[11]),
		PostOffice:  string(partsWithoutPhoto[12]),
		State:       string(partsWithoutPhoto[13]),
		Street:      string(partsWithoutPhoto[14]),
		SubDistrict: string(partsWithoutPhoto[15]),
		VTC:         string(partsWithoutPhoto[16]),
	}
	a.MobileLastDigits = string(partsWithoutPhoto[17])
	a.Photo = base64.RawStdEncoding.EncodeToString(
		(bytes.Join(photo, []byte{delimiter})),
	)

	var delimiterIndices []int
	for i, b := range a.rawdata {
		if b == 255 {
			delimiterIndices = append(delimiterIndices, i)
		}
		if len(delimiterIndices) == 18 {
			break
		}
	}

	if err = a.verify(); err != nil {
		return fmt.Errorf("failed to unmarshal from QR: %w", err)
	}

	return nil
}

type VC struct {
	Address        string
	Birthday       int
	Gender         string
	Name           string
	ReferenceID    string
	IssuanceDate   time.Time
	ExpirationDate time.Time
}

func NewVC(data *AnonAadhaarDataV2) (*VC, error) {
	if err := data.verify(); err != nil {
		return nil, fmt.Errorf("failed to verify data: %w", err)
	}

	t, _ := time.Parse(timeTemplate, data.DateOfBirth)
	birthday := t.Year()*10000 + int(t.Month())*100 + t.Day()
	expirationDate := data.SignedTime.Add(halfYearSeconds * time.Second)

	return &VC{
		Address:     data.Address.String(),
		Birthday:    birthday,
		Gender:      data.Gender,
		Name:        data.Name,
		ReferenceID: data.ReferenceID,

		IssuanceDate:   data.SignedTime,
		ExpirationDate: expirationDate,
	}, nil
}

type QrInputs struct {
	Address     *big.Int
	Birthday    *big.Int
	Gender      *big.Int
	Name        *big.Int
	ReferenceID *big.Int

	IssuanceDate   *big.Int
	ExpirationDate *big.Int

	DataPadded       []string
	DataPaddedLen    int
	DelimiterIndices []int
	Signature        []string
}

func NewQRInputs(data *AnonAadhaarDataV2) (*QrInputs, error) {
	if err := data.verify(); err != nil {
		return nil, fmt.Errorf("failed to verify data: %w", err)
	}

	t, _ := time.Parse(timeTemplate, data.DateOfBirth)
	birthday := big.NewInt(
		int64(t.Year()*10000 + int(t.Month())*100 + t.Day()),
	)

	expirationDate := data.SignedTime.Add(halfYearSeconds * time.Second)
	issuanceDateNano := new(big.Int).Mul(
		big.NewInt(0).SetInt64(
			data.SignedTime.Unix()), big.NewInt(1e9))
	expirationDateNano := new(big.Int).Mul(
		big.NewInt(0).SetInt64(
			expirationDate.Unix()), big.NewInt(1e9))

	dataPadded, dataPaddedLen, err := sha256Pad(data.rawdata, 512*3)
	if err != nil {
		return nil, fmt.Errorf("failed to pad data: %w", err)
	}

	var delimiterIndices []int
	for i, b := range data.rawdata {
		if b == 255 {
			delimiterIndices = append(delimiterIndices, i)
		}
		if len(delimiterIndices) == 18 {
			break
		}
	}

	signatureParts, err := splitToWords(
		big.NewInt(0).SetBytes(data.signature),
		big.NewInt(121),
		big.NewInt(17),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to split signature: %w", err)
	}

	addressHash, err := poseidon.HashBytes([]byte(data.Address.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to hash(address): %w", err)
	}
	genderHash, err := poseidon.HashBytes([]byte(data.Gender))
	if err != nil {
		return nil, fmt.Errorf("failed to hash(gender): %w", err)
	}
	nameHash, err := poseidon.HashBytes([]byte(data.Name))
	if err != nil {
		return nil, fmt.Errorf("failed to hash(name): %w", err)
	}
	referenceID, ok := big.NewInt(0).SetString(data.ReferenceID, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse referenceID '%s': %w", data.ReferenceID, err)
	}

	return &QrInputs{
		Address:     addressHash,
		Birthday:    birthday,
		Gender:      genderHash,
		Name:        nameHash,
		ReferenceID: referenceID,

		IssuanceDate:   issuanceDateNano,
		ExpirationDate: expirationDateNano,

		DataPadded:       uint8ArrayToCharArray(dataPadded),
		DataPaddedLen:    dataPaddedLen,
		DelimiterIndices: delimiterIndices,
		Signature:        toString(signatureParts),
	}, nil
}

// golang implementation of sha256Pad from zk-email helpers
// https://github.com/zkemail/zk-email-verify/blob/e1084969fbee16317290e4380b3837af74fea616/packages/helpers/src/sha-utils.ts#L88
func sha256Pad(m []byte, maxShaBytes int) (paddedMessage []byte, messageLen int, err error) {
	// do not modify the original message
	message := make([]byte, len(m))
	copy(message, m)

	msgLen := len(message) * 8
	msgLenBytes := int64ToBytes(int64(msgLen))

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
		paddedMessage = append(paddedMessage, int64ToBytes(0)...)
	}
	if len(paddedMessage) != maxShaBytes {
		return nil, 0, fmt.Errorf("padding to max length did not complete properly: got %d, expected %d", len(paddedMessage), maxShaBytes)
	}

	return paddedMessage, messageLen, nil
}
