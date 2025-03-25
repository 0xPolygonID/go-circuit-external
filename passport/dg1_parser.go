package passport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// dg1TagSize is the size of the group tag in bytes
const dg1TagSize = 5

// Sex represents the gender in a passport
type Sex string

const (
	Male   Sex = "M"
	Female Sex = "F"
	Other  Sex = "X"
)

// Passport represents the data structure for a TD3 type passport
type Passport struct {
	DocumentType       string // Document type (P for passport)
	IssuingCountry     string // Country code of the issuing state
	DocumentNumber     string // Passport number
	FirstName          string // Holder's names (given names)
	FullName           string // Holder's surname
	Nationality        string // Nationality of the holder
	DateOfBirth        string // Date of birth in YYMMDD format
	Sex                Sex    // Sex (M, F or X)
	DateOfExpiry       string // Date of expiry in YYMMDD format
	PersonalNumber     string // Personal number or other identification elements
	CheckDigitNumber   string // Check digit for document number
	CheckDigitDOB      string // Check digit for date of birth
	CheckDigitExpiry   string // Check digit for date of expiry
	CheckDigitPersonal string // Check digit for personal number
	CheckDigitFinal    string // Final check digit (for all data)
	Raw                []byte // Raw data including group tag
}

// ParseDG1 parses the provided DG1 data and returns a Passport struct
func ParseDG1(data string) (*Passport, error) {
	dg1Raw, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("invalid TD3 format: data should be a hexadecimal string: %w", err)
	}
	dg1RawWithoutTag := dg1Raw[dg1TagSize:]

	dg1 := string(dg1RawWithoutTag)
	if len(dg1) != 88 {
		return nil, fmt.Errorf("invalid TD3 format: data should be 88 characters long: %d", len(dg1))
	}

	line1 := dg1[:44]
	line2 := dg1[44:88]

	// Basic validation
	if !strings.HasPrefix(line1, "P") {
		return nil, errors.New("invalid TD3 format: first character should be 'P' for passport")
	}

	// Determine the sex value
	var sexValue Sex
	switch line2[20:21] {
	case "M":
		sexValue = Male
	case "F":
		sexValue = Female
	case "X":
		sexValue = Other
	default:
		sexValue = Other
	}

	passport := &Passport{
		DocumentType:       line1[:1],
		IssuingCountry:     line1[2:5],
		FirstName:          parseNames(line1[5:44]),
		FullName:           parseSurname(line1[5:44]),
		DocumentNumber:     line2[:9],
		CheckDigitNumber:   line2[9:10],
		Nationality:        line2[10:13],
		DateOfBirth:        line2[13:19],
		CheckDigitDOB:      line2[19:20],
		Sex:                sexValue,
		DateOfExpiry:       line2[21:27],
		CheckDigitExpiry:   line2[27:28],
		PersonalNumber:     strings.TrimSpace(line2[28:42]),
		CheckDigitPersonal: line2[42:43],
		CheckDigitFinal:    line2[43:44],
		Raw:                dg1Raw,
	}

	return passport, nil
}

// parseNames extracts given names from the name field
func parseNames(nameField string) string {
	// Names come after the surname in the format "SURNAME<<FIRSTNAME<MIDDLENAME"
	parts := strings.Split(nameField, "<<")
	if len(parts) < 2 {
		return ""
	}

	// Replace < with spaces in the given names
	return strings.ReplaceAll(parts[1], "<", " ")
}

// parseSurname extracts the surname from the name field
func parseSurname(nameField string) string {
	parts := strings.Split(nameField, "<<")
	if len(parts) == 0 {
		return ""
	}

	// Replace < with spaces in surname to handle multiple surnames
	return strings.ReplaceAll(parts[0], "<", " ")
}
