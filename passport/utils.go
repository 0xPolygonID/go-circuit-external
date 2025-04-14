package passport

import (
	"fmt"
	"strconv"
	"time"
)

const (
	circomYearSeconds = 31536000
)

// FormatDate formats date to 8 digits format
// TODO (illia-korotia): Test each case with the same data here and in the circuit.
func formatDate(date, currentDate int) int {
	if date > currentDate {
		return 19000000 + date
	}
	return 20000000 + date
}

func intToTime(dateInt int) time.Time {
	year := dateInt / 10000
	month := (dateInt % 10000) / 100
	day := dateInt % 100
	return time.Date(
		year,
		time.Month(month),
		day,
		0, 0, 0, 0, time.UTC,
	)
}

// dateOfBirth and dateOfExpiry are provided in YYMMDD format from passport
// this function uses issuanceDate(time.Now) do define the year.
func convertData(today time.Time, dateOfBirth, dateOfExpiry string) (
	dob, doe time.Time, err error,
) {
	dobInt, err := strconv.Atoi(dateOfBirth)
	if err != nil {
		return time.Time{}, time.Time{},
			fmt.Errorf("failed to convert date of birth to int: %w", err)
	}
	expiryInt, err := strconv.Atoi(dateOfExpiry)
	if err != nil {
		return time.Time{}, time.Time{},
			fmt.Errorf("failed to convert date of expiry to int: %w", err)
	}
	todayInt, err := strconv.Atoi(today.Format("060102"))
	if err != nil {
		return time.Time{}, time.Time{},
			fmt.Errorf("failed to convert issuance date to int: %w", err)
	}

	// define dob
	dobInt = formatDate(dobInt, todayInt)

	// define doe
	if expiryInt < todayInt {
		return time.Time{}, time.Time{},
			fmt.Errorf("passport is expired")
	}
	expiryInt += 20000000

	return intToTime(dobInt), intToTime(expiryInt), nil
}

func calculateExpirationDate(passportExpirationDate, currentDate time.Time) time.Time {
	diff := passportExpirationDate.Sub(currentDate)
	if diff.Seconds() < 31536000 {
		return passportExpirationDate
	}
	return currentDate.Add(circomYearSeconds * time.Second)
}
