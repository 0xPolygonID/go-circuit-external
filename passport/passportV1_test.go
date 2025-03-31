package passport

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestW3CCredential(t *testing.T) {
	issuanceDate, err := time.Parse(time.RFC3339Nano, "2025-03-21T17:28:52.201289Z")
	require.NoError(t, err)

	inputs := PassportV1Inputs{
		PassportData:                    mrzToDg1("P<UKRKUZNETSOV<<VALERIY<<<<<<<<<<<<<<<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02"),
		DG2Hash:                         "88328f6e5066315192a573911a6f33081da50fd51397af13edb3d7badbb59f98",
		IssuerID:                        "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
		CredentialSubjectID:             "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
		CredentialStatusRevocationNonce: 0,
		CredentialStatusID:              "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2&state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
		IssuanceDate:                    issuanceDate.UTC().Unix(),
		LinkNonce:                       "1",
	}
	jsonInputs, err := json.Marshal(inputs)
	require.NoError(t, err)
	fmt.Println(string(jsonInputs))

	credential, err := inputs.W3CCredential()
	require.NoError(t, err)
	b, err := json.MarshalIndent(credential, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))
}

func TestInputsMarshal(t *testing.T) {
	issuanceDate, err := time.Parse(time.RFC3339Nano, "2025-03-21T17:28:52.201289Z")
	require.NoError(t, err)

	inputs := PassportV1Inputs{
		PassportData:                    mrzToDg1("P<UKRKUZNETSOV<<VALERIY<<<<<<<<<<<<<<<<<<<<<AC12345674UKR9603091M3508035<<<<<<<<<<<<<<02"),
		DG2Hash:                         "88328f6e5066315192a573911a6f33081da50fd51397af13edb3d7badbb59f98",
		IssuerID:                        "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
		CredentialSubjectID:             "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
		CredentialStatusRevocationNonce: 0,
		CredentialStatusID:              "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2&state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
		IssuanceDate:                    issuanceDate.UTC().Unix(),
		LinkNonce:                       "1",
	}

	inputsCircuit, err := inputs.InputsMarshal()
	require.NoError(t, err)
	fmt.Println(string(inputsCircuit))
}

func TestInputsUnmarshal(t *testing.T) {
	publicOutputs := []string{
		"12343105779965610540047025345938704312955329035594806470260411576419571786879",
		"14193146200435563417722817655626671239476419932450502386457224894805250323461",
		"16124395655319932562687594154333620461512120815155591900166934828565073655159",
		"779590574833975594150553032190316165100034337907701477766077549696170325957",
		"3286800018689036072036595048281161368331306321215602580795106602635276597696",
		"14193146200435563417722817655626671239476419932450502386457224894805250323461",
		"19960309",
		"4366613503740245542741816499068547859478657796760861141829344679607332353738",
		"20350803",
		"6632588972401112452204984525927531300077823504377975214483036229186777300654",
		"20661880459224054680311568334655353588113926319608771155576598304028828385849",
		"17688680066341107134455191079814377222217258245657465909100070052329567309045",
		"250321",
		"1742578132000000000",
		"1032673590281623375551861967557659243242098504285449195937994191670285259560",
	}
	jsonPublicOutputs, err := json.Marshal(publicOutputs)
	require.NoError(t, err)

	expected := PassportV1PubSignals{}
	err = expected.PubSignalsUnmarshal(jsonPublicOutputs)
	require.NoError(t, err)

	require.Equal(t, expected.HashIndex, publicOutputs[9])
	require.Equal(t, expected.HashValue, publicOutputs[10])
	require.Equal(t, expected.LinkId, publicOutputs[11])
	require.Equal(t, expected.CurrentDate, publicOutputs[12])
	require.Equal(t, expected.IssuanceDate, publicOutputs[13])
	require.Equal(t, expected.TemplateRoot, publicOutputs[14])
}
