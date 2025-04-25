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

func (a *AnonAadhaarDataV2) UnmarshalQR(data *big.Int) error {
	r, err := createDecompressor(data.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create zlib/gzip reader: %w", err)
	}
	//nolint:errcheck // Ignore close error
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

	// convert dob to time
	dob, err := time.Parse(mm_dd_yyyy_template, string(partsWithoutPhoto[4]))
	if err != nil {
		return fmt.Errorf(
			"failed to parse date of birth '%s': %w",
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
		return fmt.Errorf("failed to parse signed time '%s': %w",
			string(partsWithoutPhoto[2][4:14]), err)
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
		return fmt.Errorf("failed to unmarshal from QR: %w", err)
	}

	return nil
}
