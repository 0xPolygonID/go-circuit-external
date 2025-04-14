package passport

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// DG1 is the same as the MRZ data, but with a group tag at the beginning.
func mrzToDg1(mrz string) string {
	tag := []byte{97, 91, 95, 31, 88}
	mrzBytes := []byte(mrz)
	b := append(tag, mrzBytes...)
	return hex.EncodeToString(b)
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
				FirstName:      "VALERIY",
				FullName:       "KUZNETSOV",
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
				FirstName:      "VALERIY ALEX",
				FullName:       "KUZNETSOV MELENDEZ",
				Nationality:    "UKR",
				DateOfBirth:    "960309",
				Sex:            Male,
				DateOfExpiry:   "350803",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDG1(mrzToDg1(tt.input))
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
			require.Equal(t, tt.expected.FirstName, result.FirstName, "FirstName mismatch")
			require.Equal(t, tt.expected.FullName, result.FullName, "FullName mismatch")
			require.Equal(t, tt.expected.Nationality, result.Nationality, "Nationality mismatch")
			require.Equal(t, tt.expected.DateOfBirth, result.DateOfBirth, "DateOfBirth mismatch")
			require.Equal(t, tt.expected.Sex, result.Sex, "Sex mismatch")
			require.Equal(t, tt.expected.DateOfExpiry, result.DateOfExpiry, "DateOfExpiry mismatch")
		})
	}
}
