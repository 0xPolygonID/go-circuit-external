package passport

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// DG1 is the same as the MRZ data, but with a group tag at the beginning.
func mrzToDg1_TD3(mrz string) []byte {
	tag := []byte{97, 91, 95, 31, 88}
	mrzBytes := []byte(mrz)
	b := append(tag, mrzBytes...)
	return b
}

func mrzToDg1_TD1(mrz string) []byte {
	tag := []byte{97, 93, 95, 31, 90}
	mrzBytes := []byte(mrz)
	b := append(tag, mrzBytes...)
	return b
}

func TestParseDG1(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    *Passport
		shouldError bool
	}{
		{
			name:  "Valid TD3 passport with hex data and group tag",
			input: "P<UKRKUZNETSOV<<VALERIY<<<<<<<<<<<<<<<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02",
			expected: &Passport{
				DocumentType:   "P",
				IssuingCountry: "UKR",
				DocumentNumber: "AC1234567",
				HolderName:     "KUZNETSOV  VALERIY",
				Nationality:    "UKR",
				DateOfBirth:    "960309",
				Sex:            Male,
				DateOfExpiry:   "350803",
			},
		},
		{
			name:  "Valid TD3 passport with hex data and group tag. Double fullname",
			input: "P<UKRKUZNETSOV<MELENDEZ<<VALERIY<ALEX<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02",
			expected: &Passport{
				DocumentType:   "P",
				IssuingCountry: "UKR",
				DocumentNumber: "AC1234567",
				HolderName:     "KUZNETSOV MELENDEZ  VALERIY ALEX",
				Nationality:    "UKR",
				DateOfBirth:    "960309",
				Sex:            Male,
				DateOfExpiry:   "350803",
			},
		},
		{
			name:  "Valid TD3 passport with hex data and group tag",
			input: "PMUKRKUZNETSOV<<VALERIY<<<<<<<<<<<<<<<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02",
			expected: &Passport{
				DocumentType:   "PM",
				IssuingCountry: "UKR",
				DocumentNumber: "AC1234567",
				HolderName:     "KUZNETSOV  VALERIY",
				Nationality:    "UKR",
				DateOfBirth:    "960309",
				Sex:            Male,
				DateOfExpiry:   "350803",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTD3(mrzToDg1_TD3(tt.input))
			require.NoError(t, err)

			// Check each field individually for better error messages
			require.Equal(t, tt.expected.DocumentType, result.DocumentType, "DocumentType mismatch")
			require.Equal(
				t,
				tt.expected.IssuingCountry,
				result.IssuingCountry,
				"IssuingCountry mismatch",
			)
			require.Equal(
				t,
				tt.expected.DocumentNumber,
				result.DocumentNumber,
				"DocumentNumber mismatch",
			)
			require.Equal(t, tt.expected.HolderName, result.HolderName, "HolderName mismatch")
			require.Equal(t, tt.expected.Nationality, result.Nationality, "Nationality mismatch")
			require.Equal(t, tt.expected.DateOfBirth, result.DateOfBirth, "DateOfBirth mismatch")
			require.Equal(t, tt.expected.Sex, result.Sex, "Sex mismatch")
			require.Equal(t, tt.expected.DateOfExpiry, result.DateOfExpiry, "DateOfExpiry mismatch")
		})
	}
}

func TestParseDG1_TD1(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    *Passport
		shouldError bool
	}{
		{
			name:  "Valid TD1 document - Common id card",
			input: "IDUKRAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4KUZNETSOV<<VALERIY<<<<<<<<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC1234567",
				HolderName:       "KUZNETSOV  VALERIY",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Short document type",
			input: "I<UKRAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4KUZNETSOV<<VALERIY<<<<<<<<<<<<",
			expected: &Passport{
				DocumentType:     "I",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC1234567",
				HolderName:       "KUZNETSOV  VALERIY",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Shord document number",
			input: "IDUKRAC12345<<1<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4KUZNETSOV<<VALERIY<<<<<<<<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC12345",
				HolderName:       "KUZNETSOV  VALERIY",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Optional identifier present",
			input: "IDUKRAC12345<<112345<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4KUZNETSOV<<VALERIY<<<<<<<<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC12345",
				HolderName:       "KUZNETSOV  VALERIY",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Double given name",
			input: "IDUKRAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4KUZNETSOV<<VALERIY<VICTOR<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC1234567",
				HolderName:       "KUZNETSOV  VALERIY VICTOR",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Long name: triple given name",
			input: "IDUKRAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4LUCA<<MATTEO<ROSSI<BIAN<<<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC1234567",
				HolderName:       "LUCA  MATTEO ROSSI BIAN",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Long name: double surname and given name",
			input: "IDUKRAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4LUCA<MATTEO<<ROSSI<BIAN<<<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC1234567",
				HolderName:       "LUCA MATTEO  ROSSI BIAN",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Different nationality and issuing country",
			input: "IDESPAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4LUCA<MATTEO<<ROSSI<BIAN<<<<<<<",
			expected: &Passport{
				DocumentType:     "ID",
				IssuingCountry:   "ESP",
				DocumentNumber:   "AC1234567",
				HolderName:       "LUCA MATTEO  ROSSI BIAN",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Only name",
			input: "I<UKRAC12345671<<<<<<<<<<<<<<<9603092M3508033UKR<<<<<<<<<<<4ONLYNAME<<<<<<<<<<<<<<<<<<<<<<",
			expected: &Passport{
				DocumentType:     "I",
				IssuingCountry:   "UKR",
				DocumentNumber:   "AC1234567",
				HolderName:       "ONLYNAME",
				Nationality:      "UKR",
				DateOfBirth:      "960309",
				Sex:              Male,
				DateOfExpiry:     "350803",
				CheckDigitNumber: "1",
				CheckDigitDOB:    "2",
				CheckDigitExpiry: "3",
				CheckDigitFinal:  "4",
			},
		},
		{
			name:  "Valid TD1 document - Minimal values",
			input: "I<<<<<<<<<<<<<0<<<<<<<<<<<<<<<0000000M0000000<<<<<<<<<<<<<<0<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",
			expected: &Passport{
				DocumentType:     "I",
				IssuingCountry:   "",
				DocumentNumber:   "",
				DateOfBirth:      "000000",
				Sex:              Male,
				DateOfExpiry:     "000000",
				CheckDigitNumber: "0",
				CheckDigitDOB:    "0",
				CheckDigitExpiry: "0",
				CheckDigitFinal:  "0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTD1(mrzToDg1_TD1(tt.input))
			require.NoError(t, err)
			// Check each field individually for better error messages
			require.Equal(t, tt.expected.DocumentType, result.DocumentType, "DocumentType mismatch")
			require.Equal(
				t,
				tt.expected.IssuingCountry,
				result.IssuingCountry,
				"IssuingCountry mismatch",
			)
			require.Equal(
				t,
				tt.expected.DocumentNumber,
				result.DocumentNumber,
				"DocumentNumber mismatch",
			)
			require.Equal(t, tt.expected.DateOfBirth, result.DateOfBirth, "DateOfBirth mismatch")
			require.Equal(t, tt.expected.Sex, result.Sex, "Sex mismatch")
			require.Equal(t, tt.expected.DateOfExpiry, result.DateOfExpiry, "DateOfExpiry mismatch")
			require.Equal(t, tt.expected.Nationality, result.Nationality, "Nationality mismatch")
			require.Equal(t, tt.expected.HolderName, result.HolderName, "HolderName mismatch")

			// check check sum digits
			require.Equal(
				t,
				tt.expected.CheckDigitNumber,
				result.CheckDigitNumber,
				"CheckDigitNumber mismatch",
			)
			require.Equal(
				t,
				tt.expected.CheckDigitDOB,
				result.CheckDigitDOB,
				"CheckDigitDOB mismatch",
			)
			require.Equal(
				t,
				tt.expected.CheckDigitExpiry,
				result.CheckDigitExpiry,
				"CheckDigitExpiry mismatch",
			)
			require.Equal(
				t,
				tt.expected.CheckDigitFinal,
				result.CheckDigitFinal,
				"CheckDigitFinal mismatch",
			)

			// Verify raw data is present
			require.NotEmpty(t, result.Raw, "Raw data should not be empty")
		})
	}
}
