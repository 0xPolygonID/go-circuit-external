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
	newleaf("4809579517396073186705705159186899409599314609122482090560534255195823961763", "15740774959206304300569618599869272754286189696397051571631518488419809088501"),  // credentialSubject.type
	newleaf("12891444986491254085560597052395677934694594587847693550621945641098238258096", "1173248646377539879946536107369421994820880702773342056419798525241229208349"),  // credentialStatus.type
	newleaf("1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962"),   // credentialSchema.type
	newleaf("14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370"),  // type.id
	newleaf("18943208076435454904128050626016920086499867123501959273334294100443438004188", "15740774959206304300569618599869272754286189696397051571631518488419809088501"), // type.id
	newleaf("2282658739689398501857830040602888548545380116161185117921371325237897538551", "6871229518191218656058751484443257943894148319679406049416377341576591110412"),   // credentialSchema.id
}

var updateTemplate = []leaf{
	newleaf("11718818292802126417463134214212976082628052906423225153106612749610200183413", "0"), // credentialSubject.dateOfBirth
	newleaf("17067102995727523284306589033691644246394899863627321097385336370172459010471", "0"), // credentialSubject.documentExpirationDate
	newleaf("396948171793807448670779079530437970230319997763427297159364741404168161086", "0"),   // credentialSubject.firstName
	newleaf("1540185022550171417964535586735569210235830901649938832989137234790618138161", "0"),  // credentialSubject.fullName
	newleaf("11665818515976908772146086926627988937767272157525043131077389782866401822622", "0"), // credentialSubject.govermentIdentifier
	newleaf("20378936560477526294120993552723258097975107008215368308010022877877877266947", "0"), // credentialSubject.governmentIdentifierType
	newleaf("10966443938224095219566683003147654763133050970169721700346734909387575337367", "0"), // credentialSubject.sex
	newleaf("18652354674254268839450839640508993614932212252620036777561285260846450401086", "0"), // credentialStatus.revocationNonce
	newleaf("11896622783611378286548274235251973588039499084629981048616800443645803129554", "0"), // credentialStatus.id
	newleaf("4792130079462681165428511201253235850015648352883240577315026477780493110675", "0"),  // credentialSubject.id
	newleaf("13483382060079230067188057675928039600565406666878111320562435194759310415773", "0"), // expirationDate.id
	newleaf("8713837106709436881047310678745516714551061952618778897121563913918335939585", "0"),  // issuanceDate.id
	newleaf("5940025296598751562822259677636111513267244048295724788691376971035167813215", "0"),  // issuer.id
	newleaf("9656117739891539357123771284552289598577388060024608839018723118201732735699", "0"),  // credentialSubject.nationalities.documentNationalityHash
	newleaf("15699466668150257351625206938060640380549592812731019574696943258403707765146", "0"), // credentialSubject.nationalities.documentIssuerHash
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
