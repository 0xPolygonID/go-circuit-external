package basicPersonV1_43

import (
	"fmt"
	"time"

	"github.com/0xPolygonID/go-circuit-external/common"
	template "github.com/0xPolygonID/go-circuit-external/template"
	"github.com/google/uuid"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

// Package with predictable templates for JSON-LD schemas

const (
	BasicPersonV1_43_JSON_LD = "ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL"
	BasicPersonV1_43_JSON    = "ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef"
	BasicPersonV1_43_Type    = "BasicPerson"
)

// BasicPersonV1_43 represents: https://tools.privado.id/schemas/c751b10f-6ef7-4564-be9b-925d5b130795
var BasicPersonV1_43 = []template.Node{
	template.NewNode(
		"4809579517396073186705705159186899409599314609122482090560534255195823961763",
		"3930329666255035859341917616531724337843722428795107776052883525249467734017",
	), // credentialSubject.type
	template.NewNode(
		"12891444986491254085560597052395677934694594587847693550621945641098238258096",
		"1173248646377539879946536107369421994820880702773342056419798525241229208349",
	), // credentialStatus.type
	template.NewNode(
		"1876843462791870928827702802899567513539510253808198232854545117818238902280",
		"6863952743872184967730390635778205663409140607467436963978966043239919204962",
	), // credentialSchema.type
	template.NewNode(
		"14122086068848155444790679436566779517121339700977110548919573157521629996400",
		"8932896889521641034417268999369968324098807262074941120983759052810017489370",
	), // type.id
	template.NewNode(
		"18943208076435454904128050626016920086499867123501959273334294100443438004188",
		"3930329666255035859341917616531724337843722428795107776052883525249467734017",
	), // type.id
	template.NewNode(
		"2282658739689398501857830040602888548545380116161185117921371325237897538551",
		"6785128192015566537155412245008504798482626052796872471438218406454907503679",
	), // credentialSchema.id
}

// List of known keys for the BasicPersonV1_43 template.
var (
	DateOfBirth = common.MustBigInt(
		"4817156672888655522763064392525239094511187154831557262772815264540847425378",
	)
	DocumentExpirationDate = common.MustBigInt(
		"2661316897620170050641842010022238582485958559445913964628121513401804945508",
	)
	FirstName = common.MustBigInt(
		"17812501853592608022106438142029031484125620705472224666715824544873239913147",
	)
	FullName = common.MustBigInt(
		"643493878926457766162531104335565260785288743937125657511062755781004518297",
	)
	GovernmentIdentifier = common.MustBigInt(
		"5768075745493428917651844471684022554030750947591103713762344570867180513614",
	)
	GovernmentIdentifierType = common.MustBigInt(
		"12037662945351652395520680282306597407040165994104304811455681806232413956620",
	)
	Sex = common.MustBigInt(
		"16829829523990922339853122033176330960757159233571217495904710638791793740933",
	)
	RevocationNonce = common.MustBigInt(
		"18652354674254268839450839640508993614932212252620036777561285260846450401086",
	)
	CredentialStatusID = common.MustBigInt(
		"11896622783611378286548274235251973588039499084629981048616800443645803129554",
	)
	CredentialSubjectID = common.MustBigInt(
		"4792130079462681165428511201253235850015648352883240577315026477780493110675",
	)
	ExpirationDate = common.MustBigInt(
		"13483382060079230067188057675928039600565406666878111320562435194759310415773",
	)
	IssuanceDate = common.MustBigInt(
		"8713837106709436881047310678745516714551061952618778897121563913918335939585",
	)
	Issuer = common.MustBigInt(
		"5940025296598751562822259677636111513267244048295724788691376971035167813215",
	)
	DocumentNationality = common.MustBigInt(
		"12721581730399791084220775389224758160887300573168177512619749567794685336757",
	)
	DocumentIssuer = common.MustBigInt(
		"8420111610095993874869544651671831438228943062702729758375308097770323355054",
	)
	Gender = common.MustBigInt(
		"5404445087797932868809306015538218496376343675339731487859545200224329791072",
	)
	AddressLine1 = common.MustBigInt(
		"2789441998411353097504888849796647342929687866714787904727157138859134659534",
	)
)

// WithIssuanceDate is optional parameter for setting IssuanceDate.
func WithIssuanceDate(issuanceDate time.Time) func(*verifiable.W3CCredential) {
	return func(cred *verifiable.W3CCredential) {
		if !issuanceDate.IsZero() {
			cred.IssuanceDate = &issuanceDate
		}
	}
}

// WithExpiration is optional parameter for setting Expiration.
func WithExpiration(expiration time.Time) func(*verifiable.W3CCredential) {
	return func(cred *verifiable.W3CCredential) {
		if !expiration.IsZero() {
			cred.Expiration = &expiration
		}
	}
}

func BuildBasicPersonV1_43Credential(
	credentialSubject map[string]interface{},
	credentialStatus *verifiable.CredentialStatus,
	issuerDID string,
	options ...func(*verifiable.W3CCredential),
) (verifiable.W3CCredential, error) {
	if credentialSubject == nil {
		return verifiable.W3CCredential{}, fmt.Errorf("credentialSubject is nil")
	}
	credentialSubject["type"] = BasicPersonV1_43_Type

	credential := verifiable.W3CCredential{
		ID: fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Context: []string{
			verifiable.JSONLDSchemaW3CCredential2018,
			verifiable.JSONLDSchemaIden3Credential,
			BasicPersonV1_43_JSON_LD,
		},
		Type: []string{
			verifiable.TypeW3CVerifiableCredential,
			BasicPersonV1_43_Type,
		},
		CredentialSubject: credentialSubject,
		CredentialStatus:  credentialStatus,
		Issuer:            issuerDID,
		CredentialSchema: verifiable.CredentialSchema{
			ID:   BasicPersonV1_43_JSON,
			Type: verifiable.JSONSchema2023,
		},
	}

	for _, opt := range options {
		opt(&credential)
	}

	return credential, nil
}
