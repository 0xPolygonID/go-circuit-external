package passport

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestW3CCredential(t *testing.T) {
	//nolint:gosec // Test data
	expectedCredential := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL"
  ],
  "type": [
    "VerifiableCredential",
    "BasicPerson"
  ],
  "expirationDate": "2026-03-21T17:28:52Z",
  "issuanceDate": "2025-03-21T17:28:52Z",
  "credentialSubject": {
    "dateOfBirth": 19960309,
    "documentExpirationDate": 20350803,
    "firstName": "VALERIY",
    "fullName": "KUZNETSOV",
    "governmentIdentifier": "AC1234567",
    "governmentIdentifierType": "P",
    "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
    "nationalities": {
      "nationality1CountryCode": "UKR",
      "nationality2CountryCode": "UKR"
    },
    "sex": "M",
    "type": "BasicPerson"
  },
  "credentialStatus": {
    "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2\u0026state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
    "type": "Iden3OnchainSparseMerkleTreeProof2023",
    "revocationNonce": 0
  },
  "issuer": "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
  "credentialSchema": {
    "id": "ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef",
    "type": "JsonSchema2023"
  }
}`

	issuanceDate, err := time.Parse(time.RFC3339Nano, "2025-03-21T17:28:52.201289Z")
	require.NoError(t, err)

	inputs := PassportV1Inputs{
		PassportData:                    mrzToDg1("P<UKRKUZNETSOV<<VALERIY<<<<<<<<<<<<<<<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02"),
		IssuerID:                        "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
		CredentialSubjectID:             "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
		CredentialStatusRevocationNonce: 0,
		CredentialStatusID:              "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2&state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
		IssuanceDate:                    issuanceDate.UTC().Unix(),
		LinkNonce:                       "1",
	}

	credential, err := inputs.W3CCredential()
	require.NoError(t, err)
	credential.ID = ""
	actualCredential, err := json.Marshal(credential)
	require.NoError(t, err)

	require.JSONEq(t, expectedCredential, string(actualCredential))
}

func TestInputsMarshal(t *testing.T) {
	issuanceDate, err := time.Parse(time.RFC3339Nano, "2025-03-21T17:28:52.201289Z")
	require.NoError(t, err)

	inputs := PassportV1Inputs{
		PassportData:                    mrzToDg1("P<UKRKUZNETSOV<<VALERIY<<<<<<<<<<<<<<<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02"),
		IssuerID:                        "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
		CredentialSubjectID:             "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
		CredentialStatusRevocationNonce: 0,
		CredentialStatusID:              "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2&state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
		IssuanceDate:                    issuanceDate.UTC().Unix(),
		LinkNonce:                       "1",
	}

	inputsCircuit, err := inputs.InputsMarshal(context.Background())
	require.NoError(t, err)
	expectedInputs, err := os.ReadFile("./testdata/inputs.json")
	require.NoError(t, err)
	require.JSONEq(t, string(expectedInputs), string(inputsCircuit))
}

func TestInputsUnmarshal(t *testing.T) {
	publicInputs, err := os.ReadFile("./testdata/outputs.json")
	require.NoError(t, err)

	signals := &PassportV1PubSignals{}
	err = signals.PubSignalsUnmarshal(publicInputs)
	require.NoError(t, err)

	expected := PassportV1PubSignals{
		HashIndex:    "12540426411710453760151393601170235972829881381898755539806736392337874991081",
		HashValue:    "20008859012517445819901041236908823100073815023181291226591238728478957482360",
		LinkID:       "17688680066341107134455191079814377222217258245657465909100070052329567309045",
		CurrentDate:  "250321",
		IssuanceDate: "1742578132",
		TemplateRoot: "3532467563022391950170321692541635800576371972220969617740093781820662149190",
	}

	require.Equal(t, expected, *signals)
}
