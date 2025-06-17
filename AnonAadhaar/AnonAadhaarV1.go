package anonaadhaar

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/0xPolygonID/go-circuit-external/common"
	"github.com/0xPolygonID/go-circuit-external/template"
	basicPerson "github.com/0xPolygonID/go-circuit-external/template/templates/basicPersonV1_43"
	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

const (
	templateSize    = 9
	halfYearSeconds = 15776640 // 6 months in seconds. Equalt to circuit implementation

	AnonAadhaarV1 circuits.CircuitID = "anonAadhaarV1"
)

var (
	zero = big.NewInt(0)

	anonAadhaarTemplate = []template.Node{
		{basicPerson.DateOfBirth, zero},
		{basicPerson.FullName, zero},
		{basicPerson.Gender, zero},
		{basicPerson.GovernmentIdentifier, zero},
		{basicPerson.GovernmentIdentifierType, zero},
		{basicPerson.RevocationNonce, zero},
		{basicPerson.AddressLine1, zero},
		{basicPerson.CredentialStatusID, zero},
		{basicPerson.CredentialSubjectID, zero},
		{basicPerson.ExpirationDate, zero},
		{basicPerson.IssuanceDate, zero},
		{basicPerson.Issuer, zero},
		{basicPerson.DocumentIssuer, zero},
	}

	countryOfIssuance = "IND" // iso3166 country code for India
)

func calculateDOE(issuanceDate time.Time) time.Time {
	expirationDate := issuanceDate.Add(halfYearSeconds * time.Second)
	return expirationDate
}

type AnonAadhaarV1Inputs struct {
	QRData *big.Int `json:"qrData"`
	// Generated on mobile app values
	CredentialSubjectID             string `json:"credentialSubjectID"`             // credentialSubject.id
	CredentialStatusRevocationNonce int    `json:"credentialStatusRevocationNonce"` // credentialStatus.revocationNonce
	CredentialStatusID              string `json:"credentialStatusID"`              // credentialStatus.id
	// Mobile dynamic values with Firebase config
	IssuerID      string `json:"issuerID"`      // issuer
	PubKey        string `json:"pubKey"`        // pubKey
	NullifierSeed int    `json:"nullifierSeed"` // nullifierSeed
	SignalHash    int    `json:"signalHash"`    // signalHash
	TimeNow       int64  `json:"timeNow"`       // current time in seconds since epoch
}

type anonAadhaarV1CircuitInputs struct {
	QRDataPadded        []string   `json:"qrDataPadded"`
	QRDataPaddedLength  int        `json:"qrDataPaddedLength"`
	DelimiterIndices    []int      `json:"delimiterIndices"`
	Signature           []string   `json:"signature"`
	PubKey              []string   `json:"pubKey"`
	NullifierSeed       int        `json:"nullifierSeed"`
	SignalHash          int        `json:"signalHash"`
	RevocationNonce     int        `json:"revocationNonce"`
	CredentialStatusID  string     `json:"credentialStatusID"`
	CredentialSubjectID string     `json:"credentialSubjectID"`
	UserID              string     `json:"userID"`
	ExpirationTime      int64      `json:"expirationTime"`
	Issuer              string     `json:"issuer"`
	TemplateRoot        string     `json:"templateRoot"`
	Siblings            [][]string `json:"siblings"`
}

func (a *AnonAadhaarV1Inputs) W3CCredential() (*verifiable.W3CCredential, error) {
	QR := &AnonAadhaarDataV2{}
	err := QR.UnmarshalQR(a.QRData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal QRData: %w", err)
	}

	credentialSubject := map[string]interface{}{
		"id":                       a.CredentialSubjectID,
		"fullName":                 QR.Name,
		"dateOfBirth":              common.TimeToInt(QR.DateOfBirth),
		"governmentIdentifier":     QR.ReferenceID,
		"governmentIdentifierType": "other",
		"gender":                   QR.Gender,
		"addresses": map[string]interface{}{
			"primaryAddress": map[string]interface{}{
				"addressLine1": QR.Address.String(),
			},
		},
		"nationalities": map[string]interface{}{
			"nationality2CountryCode": countryOfIssuance,
		},
		"type": basicPerson.BasicPersonV1_43_Type,
	}
	credentialStatus := &verifiable.CredentialStatus{
		ID: a.CredentialStatusID,
		//nolint:gosec // this is a nonce
		RevocationNonce: uint64(a.CredentialStatusRevocationNonce),
		Type:            verifiable.Iden3OnchainSparseMerkleTreeProof2023,
	}

	vc, err := basicPerson.BuildBasicPersonV1_43Credential(
		credentialSubject,
		credentialStatus,
		a.IssuerID,
		basicPerson.WithIssuanceDate(QR.SignedTime),
		basicPerson.WithExpiration(calculateDOE(QR.SignedTime)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}
	return &vc, nil
}

func (a *AnonAadhaarV1Inputs) InputsMarshal() ([]byte, error) {
	ctx := context.TODO()
	tmpl, err := template.New(templateSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create template: %w", err)
	}
	err = tmpl.Upload(ctx, basicPerson.BasicPersonV1_43)
	if err != nil {
		return nil, fmt.Errorf("failed to upload template 'BasicPersonV1_43': %w", err)
	}
	err = tmpl.Upload(ctx, anonAadhaarTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to upload template 'PassportV1Template': %w", err)
	}
	templateRoot := tmpl.Root()

	ah := &AnonAadhaarDataV2{}
	err = ah.UnmarshalQR(a.QRData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal QRData: %w", err)
	}

	// List of values to hash
	valuesToHash := []struct {
		value string
		dest  **big.Int
	}{
		{ah.Address.String(), new(*big.Int)},
		{ah.Gender, new(*big.Int)},
		{ah.Name, new(*big.Int)},
		{ah.ReferenceID, new(*big.Int)},
		{"other", new(*big.Int)}, // Identifier type
		{a.CredentialStatusID, new(*big.Int)},
		{a.CredentialSubjectID, new(*big.Int)},
		{a.IssuerID, new(*big.Int)},
		{countryOfIssuance, new(*big.Int)},
	}

	// Hash all values
	for _, item := range valuesToHash {
		*item.dest, err = common.HashValue(item.value)
		if err != nil {
			return nil, fmt.Errorf("failed to hash value '%s': %w", item.value, err)
		}
	}

	// Assign hashed values
	addressHash := *valuesToHash[0].dest
	genderHash := *valuesToHash[1].dest
	nameHash := *valuesToHash[2].dest
	referenceIDHash := *valuesToHash[3].dest
	identifierTypeHash := *valuesToHash[4].dest
	credentialStatusID := *valuesToHash[5].dest
	credentialSubjetID := *valuesToHash[6].dest
	issuer := *valuesToHash[7].dest
	countryOfIssuanceHash := *valuesToHash[8].dest

	userID, err := common.DIDToID(a.CredentialSubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert did to id: %w", err)
	}

	doe := calculateDOE(ah.SignedTime)
	timeNowClient := time.Unix(a.TimeNow, 0)
	if doe.Before(timeNowClient) {
		return nil, fmt.Errorf("expiration date %s is before current time %s", doe, timeNowClient)
	}

	siblings, err := tmpl.Update(ctx, []template.Node{
		{
			basicPerson.DateOfBirth,
			big.NewInt(int64(common.TimeToInt(ah.DateOfBirth))),
		},
		{basicPerson.FullName, nameHash},
		{basicPerson.Gender, genderHash},
		{basicPerson.GovernmentIdentifier, referenceIDHash},
		{basicPerson.GovernmentIdentifierType, identifierTypeHash},
		{basicPerson.RevocationNonce, big.NewInt(int64(a.CredentialStatusRevocationNonce))},
		{basicPerson.AddressLine1, addressHash},
		{basicPerson.CredentialStatusID, credentialStatusID},
		{basicPerson.CredentialSubjectID, credentialSubjetID},
		{
			basicPerson.ExpirationDate,
			common.TimeToUnixNano(doe),
		},
		{basicPerson.IssuanceDate, common.TimeToUnixNano(ah.SignedTime)},
		{basicPerson.Issuer, issuer},
		{basicPerson.DocumentIssuer, countryOfIssuanceHash},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update template: %w", err)
	}

	qrParts, err := prepareInputs(ah)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare inputs: %w", err)
	}

	p, err := extractNfromPubKey([]byte(a.PubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to extract pubkey: %w", err)
	}
	pk, err := splitToWords(p, big.NewInt(121), big.NewInt(17))
	if err != nil {
		return nil, fmt.Errorf("failed to split pubkey: %w", err)
	}

	inputs := anonAadhaarV1CircuitInputs{
		QRDataPadded:        qrParts.dataPadded,
		QRDataPaddedLength:  qrParts.dataPaddedLen,
		DelimiterIndices:    qrParts.delimiterIndices,
		Signature:           qrParts.signature,
		PubKey:              common.BigIntListToStrings(pk),
		NullifierSeed:       a.NullifierSeed,
		SignalHash:          a.SignalHash,
		RevocationNonce:     a.CredentialStatusRevocationNonce,
		CredentialStatusID:  credentialStatusID.String(),
		CredentialSubjectID: credentialSubjetID.String(),
		UserID:              userID.BigInt().String(),
		ExpirationTime:      halfYearSeconds, // how seconds added to signed time in circuit
		Issuer:              issuer.String(),
		TemplateRoot:        templateRoot.String(),
		Siblings:            common.ConvertSiblings(siblings),
	}

	jsonBytes, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inputs: %w", err)
	}

	return jsonBytes, nil
}

// AnonAadhaarV1PubSignals public inputs.
type AnonAadhaarV1PubSignals struct {
	PubKeyHash      string
	Nullifier       string
	HashIndex       string
	HashValue       string
	IssuanceDate    string
	ExpirationDate  string
	QrVersion       int
	NullifierSeed   int
	SignalHash      int
	TemplateRoot    string
	IssuerDIDHash   string
	RevocationNonce int
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals.
func (a *AnonAadhaarV1PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// 0 - pubKeyHash
	// 1 - nullifier
	// 2 - hashIndex
	// 3 - hashValue
	// 4 - issuanceDate
	// 5 - expirationDate
	// 6 - qrVersion
	// 7 - nullifierSeed
	// 8 - signalHash
	// 9 - templateRoot
	// 10 - issuerDIDHash
	// 11 - revocationNonce

	const fieldLength = 12

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength {
		return fmt.Errorf("expected %d values, got %d", fieldLength, len(sVals))
	}

	a.PubKeyHash = sVals[0]
	a.Nullifier = sVals[1]
	a.HashIndex = sVals[2]
	a.HashValue = sVals[3]
	a.IssuanceDate = sVals[4]
	a.ExpirationDate = sVals[5]
	a.QrVersion, err = strconv.Atoi(sVals[6])
	if err != nil {
		return fmt.Errorf("failed to parse qrVersion: %w", err)
	}
	a.NullifierSeed, err = strconv.Atoi(sVals[7])
	if err != nil {
		return fmt.Errorf("failed to parse nullifierSeed: %w", err)
	}
	a.SignalHash, err = strconv.Atoi(sVals[8])
	if err != nil {
		return fmt.Errorf("failed to parse signalHash: %w", err)
	}
	a.TemplateRoot = sVals[9]
	a.IssuerDIDHash = sVals[10]
	a.RevocationNonce, err = strconv.Atoi(sVals[11])
	if err != nil {
		return fmt.Errorf("failed to parse revocationNonce: %w", err)
	}

	return nil
}

// GetObjMap returns struct field as a map.
func (a *AnonAadhaarV1PubSignals) GetObjMap() map[string]interface{} {
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

type qrParts struct {
	dataPadded       []string
	dataPaddedLen    int
	delimiterIndices []int
	signature        []string
}

func prepareInputs(data *AnonAadhaarDataV2) (*qrParts, error) {
	if err := data.verify(); err != nil {
		return nil, fmt.Errorf("failed to verify data: %w", err)
	}

	dataPadded, dataPaddedLen, err := sha256Pad(data.rawdata, 512*3)
	if err != nil {
		return nil, fmt.Errorf("failed to pad data: %w", err)
	}

	var delimiterIndices []int
	for i, b := range data.rawdata {
		if b == 255 {
			delimiterIndices = append(delimiterIndices, i)
		}
		if len(delimiterIndices) == 18 {
			break
		}
	}

	signatureParts, err := splitToWords(
		big.NewInt(0).SetBytes(data.signature),
		big.NewInt(121),
		big.NewInt(17),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to split signature: %w", err)
	}

	return &qrParts{
		dataPadded:       common.Uint8ArrayToCharArray(dataPadded),
		dataPaddedLen:    dataPaddedLen,
		delimiterIndices: delimiterIndices,
		signature:        common.BigIntListToStrings(signatureParts),
	}, nil
}
