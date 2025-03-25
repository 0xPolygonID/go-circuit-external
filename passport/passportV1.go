package passport

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

const (
	PassportV1 circuits.CircuitID = "passportV1"
)

// FormatDate formats date to 8 digits format
// TODO (illia-korotia): Test each case with the same data here and in the circuit
func formatDate(date int, currentDate int) int {
	if date > currentDate {
		return 19000000 + date
	}
	return 20000000 + date
}

type PassportV1Inputs struct {
	PassportData string `json:"passportData"`
	// Generated on mobile app values
	CredentialSubjectID             string `json:"credentialSubjectID"`             // credentialSubject.id
	CredentialStatusRevocationNonce int    `json:"credentialStatusRevocationNonce"` // credentialStatus.revocationNonce
	CredentialStatusID              string `json:"credentialStatusID"`              // credentialStatus.id
	IssuanceDate                    int64  `json:"issuanceDate"`                    // unix timestamp
	LinkNonce                       string `json:"linkNonce"`
	// Mobile dynamic values with Firebase config
	IssuerID string `json:"issuerID"` // issuer
}

type anonAadhaarV1CircuitInputs struct {
	DG1                 []int      `json:"dg1"`
	LastNameSize        int        `json:"lastNameSize"`
	FirstNameSize       int        `json:"firstNameSize"`
	CurrentDate         string     `json:"currentDate"` // format: YYMMDD
	RevocationNonce     int        `json:"revocationNonce"`
	CredentialStatusID  string     `json:"credentialStatusID"`
	CredentialSubjectID string     `json:"credentialSubjectID"`
	UserID              string     `json:"userID"`
	Issuer              string     `json:"issuer"`
	IssuanceDate        *big.Int   `json:"issuanceDate"` // unix nano timestamp
	LinkNonce           string     `json:"linkNonce"`
	TemplateRoot        string     `json:"templateRoot"`
	Siblings            [][]string `json:"siblings"`
}

func (a *PassportV1Inputs) W3CCredential() (*verifiable.W3CCredential, error) {
	dg1, err := ParseDG1(a.PassportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DG1: %w", err)
	}

	timeNow := time.Unix(int64(a.IssuanceDate), 0).UTC()
	timeNowInt, err := strconv.Atoi(
		timeNow.Format("060102"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert issuance date to int: %w", err)
	}

	dobInt, err := strconv.Atoi(dg1.DateOfBirth)
	if err != nil {
		return nil, fmt.Errorf("failed to convert date of birth to int: %w", err)
	}
	dobFormatted := formatDate(dobInt, timeNowInt)

	// TODO (illia-korotia): How to handle expiry date?
	// Do I correct it in circuits?
	expiryInt, err := strconv.Atoi(dg1.DateOfExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to convert date of expiry to int: %w", err)
	}
	if expiryInt < timeNowInt {
		return nil, fmt.Errorf("passport is expired")
	}
	expiryTime, err := time.Parse("20060102", "20"+dg1.DateOfExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry date: %w", err)
	}
	expiryTime = expiryTime.UTC()
	return &verifiable.W3CCredential{
		ID: fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
			"ipfs://QmbbizDVuzyhdqbUUk534tUKxEgxVg21QbRXZNpoNBXvcj",
		},
		Type: []string{
			"VerifiableCredential",
			"BasicPerson",
		},
		IssuanceDate: &timeNow, // TOOD (illia-korotia): should we have it in UnixNano?
		Expiration:   &expiryTime,
		CredentialSubject: map[string]interface{}{
			"dateOfBirth":              dobFormatted,
			"documentExpirationDate":   20000000 + expiryInt, // TODO (illia-korotia): fix in correct way
			"firstName":                dg1.FirstName,
			"fullName":                 dg1.FullName,
			"govermentIdentifier":      dg1.DocumentNumber,
			"governmentIdentifierType": dg1.DocumentType,
			"sex":                      dg1.Sex,
			"nationalities": map[string]interface{}{
				"nationality1CountryCode": dg1.Nationality, // TODO (illia-korotia): I'm not sure that is correct // 9656117739891539357123771284552289598577388060024608839018723118201732735699
				"nationality2CountryCode": dg1.IssuingCountry,
			},
			"id":   a.CredentialSubjectID,
			"type": "BasicPerson",
		},
		CredentialStatus: &verifiable.CredentialStatus{
			ID: a.CredentialStatusID,
			//nolint:gosec // this is a nonce
			RevocationNonce: uint64(a.CredentialStatusRevocationNonce),
			Type:            "Iden3OnchainSparseMerkleTreeProof2023",
		},
		Issuer: a.IssuerID,
		CredentialSchema: verifiable.CredentialSchema{
			ID:   "ipfs://QmR7gqw4MKRLH8XSb75LkQuNAjoKhR3kZAb1A3g7CBRE3M",
			Type: "JsonSchema2023",
		},
	}, nil
}

func (a *PassportV1Inputs) InputsMarshal() ([]byte, error) {
	mt, err := newTemplateTree()
	if err != nil {
		return nil, fmt.Errorf("failed to create template tree: %w", err)
	}
	templateRoot := mt.root()

	credentialStatusID, err := hashvalue(a.CredentialStatusID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash credentialStatusID: %w", err)
	}
	credentialSubjetID, err := hashvalue(a.CredentialSubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash credentialSubjectID for credential: %w", err)
	}
	userDID, err := w3c.ParseDID(a.CredentialSubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credentialSubjectID for claim: %w", err)
	}
	userID, err := core.IDFromDID(*userDID)
	if err != nil {
		return nil, fmt.Errorf("failed to get userID: %w", err)
	}
	issuer, err := hashvalue(a.IssuerID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash issuer: %w", err)
	}

	dg1, err := ParseDG1(a.PassportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DG1: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse DG1: %w", err)
	}

	// TODO (illia-korotia): how to refactor these blocks of code?
	// To not duplicate these code
	timeNow := time.Unix(int64(a.IssuanceDate), 0)
	timeNow = timeNow.UTC()
	timeNowInt, err := strconv.Atoi(
		timeNow.Format("060102"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert issuance date to int: %w", err)
	}

	dobInt, err := strconv.Atoi(dg1.DateOfBirth)
	if err != nil {
		return nil, fmt.Errorf("failed to convert date of birth to int: %w", err)
	}
	dobFormatted := formatDate(dobInt, timeNowInt)
	dobFormattedBigInt := big.NewInt(int64(dobFormatted))

	expiryInt, err := strconv.Atoi(dg1.DateOfExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to convert date of expiry to int: %w", err)
	}
	if expiryInt < timeNowInt {
		return nil, fmt.Errorf("passport is expired")
	}
	expiryTime, err := time.Parse("20060102", "20"+dg1.DateOfExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry date: %w", err)
	}
	expiryTimeUnixNano := expiryTime.UTC().UnixNano()

	firstNameHash, err := hashvalue(dg1.FirstName)
	if err != nil {
		return nil, fmt.Errorf("failed to hash firstName: %w", err)
	}

	fullNameHash, err := hashvalue(dg1.FullName)
	if err != nil {
		return nil, fmt.Errorf("failed to hash fullName: %w", err)
	}

	govermentIdentifierHash, err := hashvalue(dg1.DocumentNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to hash govermentIdentifier: %w", err)
	}
	govermentIdentifierTypeHash, err := hashvalue(dg1.DocumentType)
	if err != nil {
		return nil, fmt.Errorf("failed to hash govermentIdentifierType: %w", err)
	}

	sexHash, err := hashvalue(string(dg1.Sex))
	if err != nil {
		return nil, fmt.Errorf("failed to hash sex: %w", err)
	}

	notionalityHash, err := hashvalue(dg1.Nationality)
	if err != nil {
		return nil, fmt.Errorf("failed to hash notionality: %w", err)
	}

	issuingCountryHash, err := hashvalue(dg1.IssuingCountry)
	if err != nil {
		return nil, fmt.Errorf("failed to hash issuing country: %w", err)
	}

	proofs, err := mt.update(updateValues{
		DateOfBirth:              dobFormattedBigInt,
		DocumentExpirationDate:   big.NewInt(int64(20000000 + expiryInt)),
		FirstName:                firstNameHash,
		FullName:                 fullNameHash,
		GovermentIdentifier:      govermentIdentifierHash,
		GovernmentIdentifierType: govermentIdentifierTypeHash,
		Sex:                      sexHash,

		RevocationNonce:     big.NewInt(int64(a.CredentialStatusRevocationNonce)),
		CredentialStatusID:  credentialStatusID,
		CredentialSubjectID: credentialSubjetID,
		ExpirationDate:      big.NewInt(expiryTimeUnixNano), // Timestamp is seconds because the circuit will multiply it by miliseconds
		// TODO (illia-korotia): will is work on js? Do we need to have it in UnixNano?
		IssuanceDate: big.NewInt(timeNow.UnixNano()), // TODO (illia-korotia): check how Oleg do this format
		Issuer:       issuer,

		Nationality:    notionalityHash,
		IssuingCountry: issuingCountryHash,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update template tree: %w", err)
	}

	updateSyblings := make([][]string, 0, len(proofs))
	for _, p := range proofs {
		// golnag library generates one extra sibling
		// that is not needed for the circuit
		// the last sibling should be 0 all the time
		if p.Siblings[len(p.Siblings)-1].BigInt().Cmp(big.NewInt(0)) != 0 {
			return nil, fmt.Errorf("last sibling should be 0")
		}
		updateSyblings = append(updateSyblings, circuits.PrepareSiblingsStr(p.Siblings[:treeLevel], treeLevel))
	}

	inputs := anonAadhaarV1CircuitInputs{
		DG1:           toIntsArray(dg1.Raw),
		LastNameSize:  len(dg1.FullName),
		FirstNameSize: len(dg1.FirstName),
		CurrentDate:   timeNow.Format("060102"),

		RevocationNonce:     a.CredentialStatusRevocationNonce,
		CredentialStatusID:  credentialStatusID.String(),
		CredentialSubjectID: credentialSubjetID.String(),
		UserID:              userID.BigInt().String(),
		Issuer:              issuer.String(),
		IssuanceDate:        big.NewInt(timeNow.UnixNano()),

		LinkNonce:    a.LinkNonce,
		TemplateRoot: templateRoot.String(),
		Siblings:     updateSyblings,
	}

	jsonBytes, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inputs: %w", err)
	}

	return jsonBytes, nil
}

func toIntsArray(b []byte) []int {
	out := make([]int, len(b))
	for i := range b {
		out[i] = int(b[i])
	}
	return out
}

// TODO (illia-korotia): Reuse this function
func hashvalue(v interface{}) (*big.Int, error) {
	mv, err := merklize.NewValue(merklize.PoseidonHasher{}, v)
	if err != nil {
		return nil, fmt.Errorf("failed to create init merklizer: %w", err)
	}
	bv, err := mv.MtEntry()
	if err != nil {
		return nil, fmt.Errorf("failed to create merklize entry: %w", err)
	}
	return bv, nil
}

// PassportV1PubSignals public inputs
type PassportV1PubSignals struct {
	HashIndex    string `json:"hashIndex"`
	HashValue    string `json:"hashValue"`
	LinkId       string `json:"linkId"`
	CurrentDate  string `json:"currentDate"`
	IssuanceDate string `json:"issuanceDate"`
	TemplateRoot string `json:"templateRoot"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals
func (a *PassportV1PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// hashIndex - 9
	// hashValue - 10
	// linkId - 11
	// currentDate - 12
	// issuanceDate - 13
	// templateRoot - 14

	const fieldLength = 15

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength {
		return fmt.Errorf("expected %d values, got %d", fieldLength, len(sVals))
	}

	a.HashIndex = sVals[9]
	a.HashValue = sVals[10]
	a.LinkId = sVals[11]
	a.CurrentDate = sVals[12]
	a.IssuanceDate = sVals[13]
	a.TemplateRoot = sVals[14]

	return nil
}

// GetObjMap returns struct field as a map
func (a *PassportV1PubSignals) GetObjMap() map[string]interface{} {
	out := make(map[string]interface{})

	value := reflect.ValueOf(a)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		fi := typ.Field(i)
		if jsonTag := fi.Tag.Get("json"); jsonTag != "" {
			out[jsonTag] = value.Field(i).Interface()
		}
	}
	return out
}
