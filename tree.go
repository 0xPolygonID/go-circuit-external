package gocircuitexternal

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

const (
	treeLevel = 11
)

var template = []leaf{
	newleaf("4809579517396073186705705159186899409599314609122482090560534255195823961763", "18044136397532219340504477858113902412319536926328861904470139126258541621004"),  // credentialSubjectType
	newleaf("1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962"),   // credentialSchemaType
	newleaf("12891444986491254085560597052395677934694594587847693550621945641098238258096", "1173248646377539879946536107369421994820880702773342056419798525241229208349"),  // credentialStatusType
	newleaf("14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370"),  // typeID1
	newleaf("18943208076435454904128050626016920086499867123501959273334294100443438004188", "18044136397532219340504477858113902412319536926328861904470139126258541621004"), // typeDI2
	newleaf("2282658739689398501857830040602888548545380116161185117921371325237897538551", "19243507057320198934591055575874927078037223068153331352121355844260563112370"),  // credentialSchemaID
}

var updateTemplate = []leaf{
	newleaf("5751456127448789510753404233713421746509146527908451401686655956477345583635", "0"),  // birthday
	newleaf("3318836932409460099840304752914646245037097428784473403764289798361397294255", "0"),  // gender
	newleaf("20577136056191360560289490021789537473272434498034348384300827512091609823990", "0"), // pincode
	newleaf("8897442514034904468148561732177026445541775910914709988947147524594211398012", "0"),  // state
	newleaf("869216178287292699550451791460637249489035896174352372440663007714837671007", "0"),   // name
	newleaf("629149548010222773287542412947332202352013141523866783940682428978496104020", "0"),   // referenceID
	newleaf("14512998077526793570215082115945432260584365246820264616091924527413647500183", "0"), // house
	newleaf("14748159073270928381473439027869493053063595361404463415882317897916125902790", "0"), // street
	newleaf("18840556411590488415073972212467374833678687425146622931052947953548116845838", "0"), // VTC
	newleaf("4809288208205333239044399615082832123737089579183363178842081905807314191006", "0"),  // district
	newleaf("18652354674254268839450839640508993614932212252620036777561285260846450401086", "0"), // revocationNonce
	newleaf("11896622783611378286548274235251973588039499084629981048616800443645803129554", "0"), // credentialStatusID
	newleaf("4792130079462681165428511201253235850015648352883240577315026477780493110675", "0"),  // credentialSubjectID
	newleaf("13483382060079230067188057675928039600565406666878111320562435194759310415773", "0"), // expirationDate
	newleaf("8713837106709436881047310678745516714551061952618778897121563913918335939585", "0"),  // issuanceDate
	newleaf("5940025296598751562822259677636111513267244048295724788691376971035167813215", "0"),  // issuer
}

type updateValues struct {
	Birthday            *big.Int
	Gender              *big.Int
	Pincode             *big.Int
	State               *big.Int
	Name                *big.Int
	ReferenceID         *big.Int
	House               *big.Int
	Street              *big.Int
	VTC                 *big.Int
	District            *big.Int
	RevocationNonce     *big.Int
	CredentialStatusID  *big.Int
	CredentialSubjectID *big.Int
	ExpirationDate      *big.Int
	IssuanceDate        *big.Int
	Issuer              *big.Int
}

func (u *updateValues) toList() []*big.Int {
	return []*big.Int{
		u.Birthday,
		u.Gender,
		u.Pincode,
		u.State,
		u.Name,
		u.ReferenceID,
		u.House,
		u.Street,
		u.VTC,
		u.District,
		u.RevocationNonce,
		u.CredentialStatusID,
		u.CredentialSubjectID,
		u.ExpirationDate,
		u.IssuanceDate,
		u.Issuer,
	}
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
