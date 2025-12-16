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
		return nil, fmt.Errorf("failed to decode DG1 data from hex: %w", err)
	}

	//nolint:gocritic // We need len from UTF8 string
	dg1RawLen := len(string(dg1Raw))

	// compare length with tag
	switch dg1RawLen {
	case 95:
		return ParseTD1(dg1Raw)
	case 93:
		return ParseTD3(dg1Raw)
	}

	return nil, fmt.Errorf(
		"invalid DG1 format: data should be either 95 (TD1) or 93 (TD3) characters long: %d",
		dg1RawLen)
}

// ParseTD1 parses the provided DG1 data in TD1 format and returns a Passport struct.
// TD1 format consists of 3 lines of 30 characters each (total 90 characters).
func ParseTD1(data []byte) (*Passport, error) {
	dg1RawWithoutTag := data[dg1TagSize:]

	dg1 := string(dg1RawWithoutTag)
	if len(dg1) != 90 {
		return nil, fmt.Errorf(
			"invalid TD1 format: data should be 90 characters long: %d",
			len(dg1),
		)
	}

	line1 := dg1[:30]
	line2 := dg1[30:60]
	line3 := dg1[60:90]

	// Parse Line 1: Document code (2), Issuing state (3), Document number (9),
	// Check digit (1), Optional data (15)
	documentType := trimPlaceholder(line1[:2])
	issuingCountry := trimPlaceholder(line1[2:5])
	documentNumber := trimPlaceholder(line1[5:14])
	checkDigitNumber := trimPlaceholder(line1[14:15])

	// Parse Line 2: Date of birth (6), Check digit (1), Sex (1), Date of expiry (6),
	// Check digit (1), Nationality (3), Optional data (11), Composite check digit (1)
	dateOfBirth := trimPlaceholder(line2[:6])
	checkDigitDOB := trimPlaceholder(line2[6:7])
	sexChar := line2[7:8]
	dateOfExpiry := trimPlaceholder(line2[8:14])
	checkDigitExpiry := trimPlaceholder(line2[14:15])
	nationality := trimPlaceholder(line2[15:18])
	checkDigitFinal := trimPlaceholder(line2[29:30])

	// Parse Line 3: Name of holder (30)
	holderName := parseHolderName(line3)

	// Determine the sex value
	var sexValue Sex
	switch sexChar {
	case "M":
		sexValue = Male
	case "F":
		sexValue = Female
	case "X":
		sexValue = Other
	default:
		sexValue = Other
	}

	// Combine optional data fields

	passport := &Passport{
		DocumentType:       documentType,
		IssuingCountry:     issuingCountry,
		DocumentNumber:     documentNumber,
		HolderName:         holderName,
		Nationality:        nationality,
		DateOfBirth:        dateOfBirth,
		Sex:                sexValue,
		DateOfExpiry:       dateOfExpiry,
		PersonalNumber:     "",
		CheckDigitNumber:   checkDigitNumber,
		CheckDigitDOB:      checkDigitDOB,
		CheckDigitExpiry:   checkDigitExpiry,
		CheckDigitPersonal: "", // TD1 doesn't have a separate personal number check digit
		CheckDigitFinal:    checkDigitFinal,
		Raw:                data,
	}

	return passport, nil
}

func ParseTD3(data []byte) (*Passport, error) {
	dg1RawWithoutTag := data[dg1TagSize:]

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
		Raw:                data,
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
