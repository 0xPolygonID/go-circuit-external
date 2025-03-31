package passport

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

const (
	treeLevel = 13
)

var template = []leaf{
	newleaf("12891444986491254085560597052395677934694594587847693550621945641098238258096", "1173248646377539879946536107369421994820880702773342056419798525241229208349"), // credentialStatus.type
	newleaf("4809579517396073186705705159186899409599314609122482090560534255195823961763", "3930329666255035859341917616531724337843722428795107776052883525249467734017"),  // credentialSubject.type
	newleaf("1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962"),  // credentialSchema.type
	newleaf("14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370"), // type.id
	newleaf("18943208076435454904128050626016920086499867123501959273334294100443438004188", "3930329666255035859341917616531724337843722428795107776052883525249467734017"), // type.id
	newleaf("2282658739689398501857830040602888548545380116161185117921371325237897538551", "6785128192015566537155412245008504798482626052796872471438218406454907503679"),  // credentialSchema.id
}

var updateTemplate = []leaf{
	newleaf("4817156672888655522763064392525239094511187154831557262772815264540847425378", "0"),  // credentialSubject.dateOfBirth
	newleaf("2661316897620170050641842010022238582485958559445913964628121513401804945508", "0"),  // credentialSubject.documentExpirationDate
	newleaf("17812501853592608022106438142029031484125620705472224666715824544873239913147", "0"), // credentialSubject.firstName
	newleaf("643493878926457766162531104335565260785288743937125657511062755781004518297", "0"),   // credentialSubject.fullName
	newleaf("5768075745493428917651844471684022554030750947591103713762344570867180513614", "0"),  // credentialSubject.governmentIdentifier
	newleaf("12037662945351652395520680282306597407040165994104304811455681806232413956620", "0"), // credentialSubject.governmentIdentifierType
	newleaf("16829829523990922339853122033176330960757159233571217495904710638791793740933", "0"), // credentialSubject.sex
	newleaf("18652354674254268839450839640508993614932212252620036777561285260846450401086", "0"), // credentialStatus.revocationNonce
	newleaf("11896622783611378286548274235251973588039499084629981048616800443645803129554", "0"), // credentialStatus.id
	newleaf("4792130079462681165428511201253235850015648352883240577315026477780493110675", "0"),  // credentialSubject.id
	newleaf("13483382060079230067188057675928039600565406666878111320562435194759310415773", "0"), // expirationDate.id
	newleaf("8713837106709436881047310678745516714551061952618778897121563913918335939585", "0"),  // issuanceDate.id
	newleaf("5940025296598751562822259677636111513267244048295724788691376971035167813215", "0"),  // issuer.id
	newleaf("12721581730399791084220775389224758160887300573168177512619749567794685336757", "0"), // credentialSubject.nationalities.documentNationalityHash
	newleaf("8420111610095993874869544651671831438228943062702729758375308097770323355054", "0"),  // credentialSubject.nationalities.documentIssuerHash
	newleaf("5174935119518540357656305431208837480424139947723235187406958318762813271623", "0"),  // credentialSubject.customFields.strings3
}

type updateValues struct {
	DateOfBirth              *big.Int
	DocumentExpirationDate   *big.Int
	FirstName                *big.Int
	FullName                 *big.Int
	GovermentIdentifier      *big.Int
	GovernmentIdentifierType *big.Int
	Sex                      *big.Int
	RevocationNonce          *big.Int
	CredentialStatusID       *big.Int
	CredentialSubjectID      *big.Int
	ExpirationDate           *big.Int
	IssuanceDate             *big.Int
	Issuer                   *big.Int
	Nationality              *big.Int
	IssuingCountry           *big.Int
	Dg2Hash                  *big.Int
}

func (u *updateValues) toList() []*big.Int {
	list := []*big.Int{
		u.DateOfBirth,
		u.DocumentExpirationDate,
		u.FirstName,
		u.FullName,
		u.GovermentIdentifier,
		u.GovernmentIdentifierType,
		u.Sex,
		u.RevocationNonce,
		u.CredentialStatusID,
		u.CredentialSubjectID,
		u.ExpirationDate,
		u.IssuanceDate,
		u.Issuer,
		u.Nationality,
		u.IssuingCountry,
		u.Dg2Hash,
	}
	for _, v := range list {
		fmt.Println(v)
	}
	return list
}

type templateTree struct {
	tree *merkletree.MerkleTree
}

func newTemplateTree() (*templateTree, error) {
	treeStorage := memory.NewMemoryStorage()
	mt, err := merkletree.NewMerkleTree(context.Background(), treeStorage, treeLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create merkle tree: %w", err)
	}
	t := make([]leaf, len(template)+len(updateTemplate))
	copy(t, template)
	copy(t[len(template):], updateTemplate)

	for _, node := range t {
		err := mt.Add(context.Background(), node.key, node.value)
		if err != nil {
			return nil, fmt.Errorf("failed to add node to merkle tree: %w", err)
		}
	}
	return &templateTree{mt}, nil
}

func (t *templateTree) update(u updateValues) ([]*merkletree.CircomProcessorProof, error) {
	res := make([]*merkletree.CircomProcessorProof, 0, len(updateTemplate))
	values := u.toList()
	for i := range updateTemplate {
		p, err := t.tree.Update(context.Background(), updateTemplate[i].key, values[i])
		if err != nil {
			return nil, fmt.Errorf("failed to update node to merkle tree: %w", err)
		}
		res = append(res, p)
	}
	return res, nil
}

func (t *templateTree) root() *big.Int {
	return t.tree.Root().BigInt()
}

type leaf struct {
	key   *big.Int
	value *big.Int
}

func newleaf(key, value string) leaf {
	return leaf{mustBigInt(key), mustBigInt(value)}
}

func mustBigInt(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Sprintf("failed to parse big.Int: %s", s))
	}
	return i
}
