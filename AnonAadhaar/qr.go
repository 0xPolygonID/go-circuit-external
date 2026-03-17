package anonaadhaar

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
)

var (
	// ErrInvalidQRVersion is returned when the QR version is invalid.
	ErrInvalidQRVersion = errors.New("invalid QR version")
	// ErrInvalidQRData is returned when invalid Aadhaar QR data is provided.
	ErrInvalidQRData = errors.New("invalid QR data")
)

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
	delimiter = byte(255)
	istOffset = 19800

	mm_dd_yyyy_template = "02-01-2006"
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
	const delimiter = ";"
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
	DateOfBirth        time.Time `json:"dateOfBirth"`
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

// verify check formats.
func (a *AnonAadhaarDataV2) verify() error {
	if a.SignedTime.IsZero() {
		return errors.New("signed time is not set")
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

// UnmarshalQROpts options.
type UnmarshalQROpts struct {
	pubkey string
}

// UnmarshalQROpt is a function that modifies UnmarshalQROpts.
type UnmarshalQROpt func(*UnmarshalQROpts)

// WithPublicKey sets the public key for signature verification.
// Without the optional public key, UnmarshalQRWithOpts
// will only unmarshal the QR data without verifying the signature.
func WithPublicKey(pubkey string) func(*UnmarshalQROpts) {
	return func(opts *UnmarshalQROpts) {
		opts.pubkey = pubkey
	}
}

// UnmarshalQRWithOpts unmarshals the given QR.
func (a *AnonAadhaarDataV2) UnmarshalQRWithOpts(data *big.Int, opts ...UnmarshalQROpt) error {
	var options UnmarshalQROpts
	for _, opt := range opts {
		opt(&options)
	}

	if err := a.UnmarshalQR(data); err != nil {
		return err
	}

	if options.pubkey != "" {
		if err := verifySignature(a.rawdata, a.signature, options.pubkey); err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}
	}

	return nil
}

// Deprecated: use UnmarshalQRWithOpts instead.
func (a *AnonAadhaarDataV2) UnmarshalQR(data *big.Int) error {
	r, err := createDecompressor(data.Bytes())
	if err != nil {
		return fmt.Errorf("%w: failed to create zlib/gzip reader: %w",
			ErrInvalidQRData, err)
	}
	//nolint:errcheck // Ignore close error
	defer r.Close()
	uncompressedData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("%w: failed to read compressed data: %w",
			ErrInvalidQRData, err)
	}

	const signatureLength = 256
	if len(uncompressedData) < signatureLength {
		return fmt.Errorf("%w: uncompressed data too short: %d",
			ErrInvalidQRData, len(uncompressedData))
	}

	a.signature = uncompressedData[len(uncompressedData)-signatureLength:]

	// remove signature
	d := uncompressedData[:len(uncompressedData)-signatureLength]
	a.rawdata = d

	// remove photo part
	parts := bytes.Split(d, []byte{delimiter})
	if len(parts) < 19 {
		return fmt.Errorf("%w: invalid number of data fields: %d",
			ErrInvalidQRData, len(parts))
	}

	partsWithoutPhoto := parts[:18]
	photo := parts[18:]

	// convert dob to time
	dob, err := time.Parse(mm_dd_yyyy_template, string(partsWithoutPhoto[4]))
	if err != nil {
		return fmt.Errorf(
			"%w: failed to parse date of birth '%s': %w",
			ErrInvalidQRVersion,
			string(partsWithoutPhoto[4]),
			err,
		)
	}

	a.Version = string(partsWithoutPhoto[0])
	a.ContactIndecator = string(partsWithoutPhoto[1])
	a.ReferenceID = string(partsWithoutPhoto[2])
	a.PassportLastDigits = string(partsWithoutPhoto[2][:4])
	sigtime, err := time.Parse(
		"2006010215",
		string(partsWithoutPhoto[2][4:14]),
	) // format: YYYYMMDDHH (24 hours representation)
	if err != nil {
		return fmt.Errorf(
			"%w: failed to parse signed time '%s': %w",
			ErrInvalidQRVersion,
			string(partsWithoutPhoto[2][4:14]),
			err)
	}
	a.SignedTime = sigtime.Add(-istOffset * time.Second)
	a.Name = string(partsWithoutPhoto[3])
	a.DateOfBirth = dob
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
		return fmt.Errorf(
			"%w: failed to verify Aadhaar QR: %w",
			ErrInvalidQRVersion, err)
	}

	return nil
}
