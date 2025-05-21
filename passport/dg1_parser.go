package passport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// dg1TagSize is the size of the group tag in bytes.
const dg1TagSize = 5

// Sex represents the gender in a passport.
type Sex string

const (
	Male   Sex = "M"
	Female Sex = "F"
	Other  Sex = "X"
)

// Passport represents the data structure for a TD3 type passport.
type Passport struct {
	DocumentType       string // Document type (P for passport)
	IssuingCountry     string // Country code of the issuing state
	DocumentNumber     string // Passport number
	HolderName         string // Full name of the holder
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

// ParseDG1 parses the provided DG1 data and returns a Passport struct.
func ParseDG1(data string) (*Passport, error) {
	dg1Raw, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("invalid TD3 format: data should be a hexadecimal string: %w", err)
	}
	dg1RawWithoutTag := dg1Raw[dg1TagSize:]

	dg1 := string(dg1RawWithoutTag)
	if len(dg1) != 88 {
		return nil, fmt.Errorf(
			"invalid TD3 format: data should be 88 characters long: %d",
			len(dg1),
		)
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

	// TD3 page 53
	// https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
	passport := &Passport{
		DocumentType:       trimPlaceholder(line1[:2]),      // 2 bytes
		IssuingCountry:     trimPlaceholder(line1[2:5]),     // 3 bytes
		HolderName:         parseHolderName(line1[5:44]),    // 39 bytes
		DocumentNumber:     trimPlaceholder(line2[:9]),      // 9 bytes
		CheckDigitNumber:   trimPlaceholder(line2[9:10]),    // 1 byte
		Nationality:        trimPlaceholder(line2[10:13]),   // 3 bytes
		DateOfBirth:        trimPlaceholder(line2[13:19]),   // 6 bytes
		CheckDigitDOB:      trimPlaceholder(line2[19:20]),   // 1 byte
		Sex:                sexValue,                        // 1 byte
		DateOfExpiry:       trimPlaceholder(line2[21:27]),   // 6 bytes
		CheckDigitExpiry:   trimPlaceholder(line2[27:28]),   // 1 byte
		PersonalNumber:     strings.TrimSpace(line2[28:42]), // 14 bytes
		CheckDigitPersonal: trimPlaceholder(line2[42:43]),   // 1 byte
		CheckDigitFinal:    trimPlaceholder(line2[43:44]),   // 1 byte
		Raw:                dg1Raw,
	}

	return passport, nil
}

func parseHolderName(holder string) string {
	return strings.TrimSpace(
		strings.ReplaceAll(holder, "<", " "),
	)
}

func trimPlaceholder(value string) string {
	// Remove placeholder characters (e.g., <) from the value
	return strings.TrimRight(value, "<")
}
