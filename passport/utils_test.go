package passport

import (
	"testing"
	"time"
)

// TODO (illia-korotia): Sync with circom circuits
func TestConvertData_Success(t *testing.T) {
	tests := []struct {
		name         string
		today        time.Time
		dateOfBirth  string
		dateOfExpiry string
		expectedDOB  time.Time
		expectedDOE  time.Time
	}{
		{
			name:         "Valid dates",
			today:        time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			dateOfBirth:  "890101", // 1989-01-01
			dateOfExpiry: "251231", // 2025-12-31
			expectedDOB:  time.Date(1989, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedDOE:  time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:         "DOB in 2000s",
			today:        time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			dateOfBirth:  "050101", // 2005-01-01
			dateOfExpiry: "301231", // 2030-12-31
			expectedDOB:  time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedDOE:  time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:         "DOB equals today",
			today:        time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			dateOfBirth:  "231001", // 2023-10-01
			dateOfExpiry: "251231", // 2025-12-31
			expectedDOB:  time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			expectedDOE:  time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:         "DOE equals today",
			today:        time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			dateOfBirth:  "890101", // 1989-01-01
			dateOfExpiry: "231001", // 2023-10-01
			expectedDOB:  time.Date(1989, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedDOE:  time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dob, doe, err := convertData(tt.today, tt.dateOfBirth, tt.dateOfExpiry)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !dob.Equal(tt.expectedDOB) {
				t.Errorf("expected DOB %v, got %v", tt.expectedDOB, dob)
			}
			if !doe.Equal(tt.expectedDOE) {
				t.Errorf("expected DOE %v, got %v", tt.expectedDOE, doe)
			}
		})
	}
}

func TestDefineExpirationDate(t *testing.T) {
	tests := []struct {
		name                   string
		passportExpirationDate time.Time
		currentDate            time.Time
		expectedDate           time.Time
	}{
		{
			name:                   "Expiration within a year",
			passportExpirationDate: time.Date(2024, 9, 30, 0, 0, 0, 0, time.UTC),
			currentDate:            time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			expectedDate:           time.Date(2024, 9, 30, 0, 0, 0, 0, time.UTC),
		},
		{
			name:                   "Expiration exactly one year away",
			passportExpirationDate: time.Date(2023, 9, 30, 0, 0, 0, 0, time.UTC),
			currentDate:            time.Date(2022, 9, 30, 0, 0, 0, 0, time.UTC),
			expectedDate:           time.Date(2023, 9, 30, 0, 0, 0, 0, time.UTC),
		},
		{
			name:                   "Expiration more than a year away",
			passportExpirationDate: time.Date(2025, 9, 30, 0, 0, 0, 0, time.UTC),
			currentDate:            time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			expectedDate:           time.Date(2024, 9, 30, 0, 0, 0, 0, time.UTC),
		},
		{
			name:                   "Expiration in the past",
			passportExpirationDate: time.Date(2023, 9, 30, 0, 0, 0, 0, time.UTC),
			currentDate:            time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
			expectedDate:           time.Date(2023, 9, 30, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateExpirationDate(tt.passportExpirationDate, tt.currentDate)
			if !result.Equal(tt.expectedDate) {
				t.Errorf("expected %v, got %v", tt.expectedDate, result)
			}
		})
	}
}
