package gocircuitexternal

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

const (
	AnonAadhaarV1 circuits.CircuitID = "anonAadhaarV1"
)

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
	ah := &AnonAadhaarDataV2{}
	err := ah.UnmarshalQR(a.QRData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal QRData: %w", err)
	}
	vcpayload, err := NewVC(ah)
	if err != nil {
		return nil, fmt.Errorf("failed to create QRInputs: %w", err)
	}

	return &verifiable.W3CCredential{
		ID: fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
			"ipfs://QmbtrBk64KmdD571GTYsUgqVPrvNVuUf8sw8CkLszjyPfk",
		},
		Type: []string{
			"VerifiableCredential",
			"AnonAadhaar",
		},
		IssuanceDate: &vcpayload.IssuanceDate,
		Expiration:   &vcpayload.ExpirationDate,
		CredentialSubject: map[string]interface{}{
			"address":     vcpayload.Address,
			"dateOfBirth": vcpayload.Birthday,
			"gender":      vcpayload.Gender,
			"id":          a.CredentialSubjectID,
			"name":        vcpayload.Name,
			"type":        "AnonAadhaar",
			"referenceID": vcpayload.ReferenceID,
		},
		CredentialStatus: &verifiable.CredentialStatus{
			ID: a.CredentialStatusID,
			//nolint:gosec // this is a nonce
			RevocationNonce: uint64(a.CredentialStatusRevocationNonce),
			Type:            "Iden3OnchainSparseMerkleTreeProof2023",
		},
		Issuer: a.IssuerID,
		CredentialSchema: verifiable.CredentialSchema{
			ID:   "ipfs://QmSvcvpYSvBZPmBtetPNJ489mByFCr1DgknpQkMwH4PK3x",
			Type: "JsonSchema2023",
		},
	}, nil
}

func (a *AnonAadhaarV1Inputs) InputsMarshal() ([]byte, error) {
	mt, err := newTemplateTree()
	if err != nil {
		return nil, fmt.Errorf("failed to create template tree: %w", err)
	}
	templateRoot := mt.root()

	p, err := extractNfromPubKey([]byte(a.PubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to extract pubkey: %w", err)
	}
	pk, err := splitToWords(p, big.NewInt(121), big.NewInt(17))
	if err != nil {
		return nil, fmt.Errorf("failed to split pubkey: %w", err)
	}

	ah := &AnonAadhaarDataV2{}
	err = ah.UnmarshalQR(a.QRData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal QRData: %w", err)
	}
	qrInputs, err := NewQRInputs(ah)
	if err != nil {
		return nil, fmt.Errorf("failed to create QRInputs: %w", err)
	}

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

	proofs, err := mt.update(updateValues{
		Address:             qrInputs.Address,
		Birthday:            qrInputs.Birthday,
		Gender:              qrInputs.Gender,
		Name:                qrInputs.Name,
		ReferenceID:         qrInputs.ReferenceID,
		RevocationNonce:     big.NewInt(int64(a.CredentialStatusRevocationNonce)),
		CredentialStatusID:  credentialStatusID,
		CredentialSubjectID: credentialSubjetID,
		ExpirationDate:      qrInputs.ExpirationDate,
		IssuanceDate:        qrInputs.IssuanceDate,
		Issuer:              issuer,
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
		QRDataPadded:        qrInputs.DataPadded,
		QRDataPaddedLength:  qrInputs.DataPaddedLen,
		DelimiterIndices:    qrInputs.DelimiterIndices,
		Signature:           qrInputs.Signature,
		PubKey:              toString(pk),
		NullifierSeed:       a.NullifierSeed,
		SignalHash:          a.SignalHash,
		RevocationNonce:     a.CredentialStatusRevocationNonce,
		CredentialStatusID:  credentialStatusID.String(),
		CredentialSubjectID: credentialSubjetID.String(),
		UserID:              userID.BigInt().String(),
		ExpirationTime:      halfYearSeconds,
		Issuer:              issuer.String(),
		TemplateRoot:        templateRoot.String(),
		Siblings:            updateSyblings,
	}

	jsonBytes, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inputs: %w", err)
	}

	return jsonBytes, nil
}

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

// AnonAadhaarV1PubSignals public inputs
type AnonAadhaarV1PubSignals struct {
	PubKeyHash     string
	Nullifier      string
	HashIndex      string
	HashValue      string
	IssuanceDate   string
	ExpirationDate string
	NullifierSeed  int
	SignalHash     int
	TemplateRoot   string
	IssuerDIDHash  string
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals
func (a *AnonAadhaarV1PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// 0 - pubKeyHash
	// 1 - nullifier
	// 2 - hashIndex
	// 3 - hashValue
	// 4 - issuanceDate
	// 5 - expirationDate
	// 6 - nullifierSeed
	// 7 - signalHash
	// 8 - templateRoot
	// 9 - issuerDIDHash

	const fieldLength = 10

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
	a.NullifierSeed, err = strconv.Atoi(sVals[6])
	if err != nil {
		return fmt.Errorf("failed to parse nullifierSeed: %w", err)
	}
	a.SignalHash, err = strconv.Atoi(sVals[7])
	if err != nil {
		return fmt.Errorf("failed to parse signalHash: %w", err)
	}
	a.TemplateRoot = sVals[8]
	a.IssuerDIDHash = sVals[9]

	return nil
}

// GetObjMap returns struct field as a map
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
