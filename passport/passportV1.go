package passport

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/0xPolygonID/go-circuit-external/common"
	"github.com/0xPolygonID/go-circuit-external/template"
	basicPerson "github.com/0xPolygonID/go-circuit-external/template/templates/basicPersonV1_43"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

const (
	templateSize = 13

	//nolint:gosec // This is names of algorithms
	CredentialSHA1 = "credential_sha1"
	//nolint:gosec // This is names of algorithms
	CredentialSHA224 = "credential_sha224"
	//nolint:gosec // This is names of algorithms
	CredentialSHA256 = "credential_sha256"
	//nolint:gosec // This is names of algorithms
	CredentialSHA384 = "credential_sha384"
	//nolint:gosec // This is names of algorithms
	CredentialSHA512 = "credential_sha512"
)

var (
	zero = big.NewInt(0)

	passportTemplate = []template.Node{
		{basicPerson.DateOfBirth, zero},
		{basicPerson.DocumentExpirationDate, zero},
		{basicPerson.FirstName, zero},
		{basicPerson.FullName, zero},
		{basicPerson.GovernmentIdentifier, zero},
		{basicPerson.GovernmentIdentifierType, zero},
		{basicPerson.Sex, zero},
		{basicPerson.RevocationNonce, zero},
		{basicPerson.CredentialStatusID, zero},
		{basicPerson.CredentialSubjectID, zero},
		{basicPerson.ExpirationDate, zero},
		{basicPerson.IssuanceDate, zero},
		{basicPerson.Issuer, zero},
		{basicPerson.DocumentNationality, zero},
		{basicPerson.DocumentIssuer, zero},
	}
)

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

	timeNow := time.Unix(a.IssuanceDate, 0).UTC()
	dobTime, doeTime, err := convertData(
		timeNow,
		dg1.DateOfBirth,
		dg1.DateOfExpiry,
	)
	if err != nil {
		return nil,
			fmt.Errorf(
				"failed to convert data dob '%s', doe '%s': %w",
				dg1.DateOfBirth, dg1.DateOfExpiry, err)
	}
	credentialExpirationTime := calculateExpirationDate(doeTime, timeNow)

	credentialSubject := map[string]interface{}{
		"dateOfBirth":              common.TimeToInt(dobTime),
		"documentExpirationDate":   common.TimeToInt(doeTime),
		"firstName":                dg1.FirstName,
		"fullName":                 dg1.FullName,
		"governmentIdentifier":     dg1.DocumentNumber,
		"governmentIdentifierType": dg1.DocumentType,
		"sex":                      dg1.Sex,
		"nationalities": map[string]interface{}{
			"nationality1CountryCode": dg1.Nationality,
			"nationality2CountryCode": dg1.IssuingCountry,
		},
		"id": a.CredentialSubjectID,
	}
	credentialRevocation := &verifiable.CredentialStatus{
		ID: a.CredentialStatusID,
		//nolint:gosec // this is a nonce
		RevocationNonce: uint64(a.CredentialStatusRevocationNonce),
		Type:            verifiable.Iden3OnchainSparseMerkleTreeProof2023,
	}
	vc, err := basicPerson.BuildBasicPersonV1_43Credential(
		credentialSubject,
		credentialRevocation,
		a.IssuerID,
		basicPerson.WithIssuanceDate(timeNow),
		basicPerson.WithExpiration(credentialExpirationTime),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build credential: %w", err)
	}
	return &vc, nil
}

func (a *PassportV1Inputs) InputsMarshal() ([]byte, error) {
	ctx := context.TODO()
	tmpl, err := template.New(templateSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create template: %w", err)
	}
	err = tmpl.Upload(ctx, basicPerson.BasicPersonV1_43)
	if err != nil {
		return nil, fmt.Errorf("failed to upload template 'BasicPersonV1_43': %w", err)
	}
	err = tmpl.Upload(ctx, passportTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to upload template 'PassportV1Template': %w", err)
	}
	templateRoot := tmpl.Root()

	dg1, err := ParseDG1(a.PassportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DG1: %w", err)
	}

	timeNow := time.Unix(a.IssuanceDate, 0).UTC()
	dobTime, doeTime, err := convertData(
		timeNow,
		dg1.DateOfBirth,
		dg1.DateOfExpiry,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert data: %w", err)
	}

	credentialExpirationTime := calculateExpirationDate(doeTime, timeNow)

	// List of values to hash
	valuesToHash := []struct {
		value string
		dest  **big.Int
	}{
		{dg1.FirstName, new(*big.Int)},
		{dg1.FullName, new(*big.Int)},
		{dg1.DocumentNumber, new(*big.Int)},
		{dg1.DocumentType, new(*big.Int)},
		{string(dg1.Sex), new(*big.Int)},
		{dg1.Nationality, new(*big.Int)},
		{dg1.IssuingCountry, new(*big.Int)},
		{a.CredentialStatusID, new(*big.Int)},
		{a.CredentialSubjectID, new(*big.Int)},
		{a.IssuerID, new(*big.Int)},
	}

	// Hash all values
	for _, item := range valuesToHash {
		*item.dest, err = common.HashValue(item.value)
		if err != nil {
			return nil, fmt.Errorf("failed to hash value '%s': %w", item.value, err)
		}
	}

	// Assign hashed values
	firstNameHash := *valuesToHash[0].dest
	fullNameHash := *valuesToHash[1].dest
	govermentIdentifierHash := *valuesToHash[2].dest
	govermentIdentifierTypeHash := *valuesToHash[3].dest
	sexHash := *valuesToHash[4].dest
	notionalityHash := *valuesToHash[5].dest
	issuingCountryHash := *valuesToHash[6].dest
	credentialStatusID := *valuesToHash[7].dest
	credentialSubjetID := *valuesToHash[8].dest
	issuer := *valuesToHash[9].dest

	siblings, err := tmpl.Update(ctx, []template.Node{
		{
			basicPerson.DateOfBirth,
			big.NewInt(int64(common.TimeToInt(dobTime))),
		},
		{
			basicPerson.DocumentExpirationDate,
			big.NewInt(int64(common.TimeToInt(doeTime))),
		},
		{basicPerson.FirstName, firstNameHash},
		{basicPerson.FullName, fullNameHash},
		{basicPerson.GovernmentIdentifier, govermentIdentifierHash},
		{basicPerson.GovernmentIdentifierType, govermentIdentifierTypeHash},
		{basicPerson.Sex, sexHash},
		{basicPerson.RevocationNonce, big.NewInt(int64(a.CredentialStatusRevocationNonce))},
		{basicPerson.CredentialStatusID, credentialStatusID},
		{basicPerson.CredentialSubjectID, credentialSubjetID},
		{basicPerson.ExpirationDate, common.TimeToUnixNano(credentialExpirationTime)},
		{basicPerson.IssuanceDate, common.TimeToUnixNano(timeNow)},
		{basicPerson.Issuer, issuer},
		{basicPerson.DocumentNationality, notionalityHash},
		{basicPerson.DocumentIssuer, issuingCountryHash},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update template: %w", err)
	}

	userID, err := common.DIDToID(a.CredentialStatusID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert issuer did to id: %w", err)
	}

	inputs := anonAadhaarV1CircuitInputs{
		DG1:                 toIntsArray(dg1.Raw),
		LastNameSize:        len(dg1.FullName),
		FirstNameSize:       len(dg1.FirstName),
		CurrentDate:         timeNow.Format("060102"),
		RevocationNonce:     a.CredentialStatusRevocationNonce,
		CredentialStatusID:  credentialStatusID.String(),
		CredentialSubjectID: credentialSubjetID.String(),
		UserID:              userID.BigInt().String(),
		Issuer:              issuer.String(),
		IssuanceDate:        big.NewInt(timeNow.UTC().Unix()),
		LinkNonce:           a.LinkNonce,
		TemplateRoot:        templateRoot.String(),
		Siblings:            common.ConvertSiblings(siblings),
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

// PassportV1PubSignals public inputs.
type PassportV1PubSignals struct {
	HashIndex    string `json:"hashIndex"`
	HashValue    string `json:"hashValue"`
	LinkID       string `json:"linkId"`
	CurrentDate  string `json:"currentDate"`
	IssuanceDate string `json:"issuanceDate"`
	TemplateRoot string `json:"templateRoot"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals.
func (a *PassportV1PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// hashIndex - 1
	// hashValue - 2
	// linkId - 3
	// currentDate - 4
	// issuanceDate - 5
	// templateRoot - 6

	const fieldLength = 6

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength {
		return fmt.Errorf("expected %d values, got %d", fieldLength, len(sVals))
	}

	a.HashIndex = sVals[0]
	a.HashValue = sVals[1]
	a.LinkID = sVals[2]
	a.CurrentDate = sVals[3]
	a.IssuanceDate = sVals[4]
	a.TemplateRoot = sVals[5]

	return nil
}

// GetObjMap returns struct field as a map.
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
