package gocircuitexternal

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

const (
	treeLevel = 10
)

var template = []leaf{
	newleaf("4809579517396073186705705159186899409599314609122482090560534255195823961763", "13937869935375738291530438207726849246854098424882058382669843808897134361138"),  // credentialSubjectType
	newleaf("12891444986491254085560597052395677934694594587847693550621945641098238258096", "1173248646377539879946536107369421994820880702773342056419798525241229208349"),  // credentialStatusType
	newleaf("1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962"),   // credentialSchemaType
	newleaf("14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370"),  // typeID1
	newleaf("18943208076435454904128050626016920086499867123501959273334294100443438004188", "13937869935375738291530438207726849246854098424882058382669843808897134361138"), // typeDI2
	newleaf("2282658739689398501857830040602888548545380116161185117921371325237897538551", "15847375876994988756807947276632841424593543193215812115685159365297584441136"),  // credentialSchemaID
}

var updateTemplate = []leaf{
	newleaf("6455913366592666201648701127743652596856200808320030661139737215331945226446", "0"),  // address
	newleaf("15797492950276814745920327875668044332806138770863520646292871331376334615157", "0"), // birthday
	newleaf("11003971958055069902221764257982759506273458969119534962957641546385029132859", "0"), // gender
	newleaf("20597968245842623707356256066033564898107884665586462726478961192187480712157", "0"), // name
	newleaf("10341739212269954293228123764665245031329949711448609200469277569519636549535", "0"), // referenceID
	newleaf("18652354674254268839450839640508993614932212252620036777561285260846450401086", "0"), // revocationNonce
	newleaf("11896622783611378286548274235251973588039499084629981048616800443645803129554", "0"), // credentialStatusID
	newleaf("4792130079462681165428511201253235850015648352883240577315026477780493110675", "0"),  // credentialSubjectID
	newleaf("13483382060079230067188057675928039600565406666878111320562435194759310415773", "0"), // expirationDate
	newleaf("8713837106709436881047310678745516714551061952618778897121563913918335939585", "0"),  // issuanceDate
	newleaf("5940025296598751562822259677636111513267244048295724788691376971035167813215", "0"),  // issuer
}

type updateValues struct {
	Address             *big.Int
	Birthday            *big.Int
	Gender              *big.Int
	Name                *big.Int
	ReferenceID         *big.Int
	RevocationNonce     *big.Int
	CredentialStatusID  *big.Int
	CredentialSubjectID *big.Int
	ExpirationDate      *big.Int
	IssuanceDate        *big.Int
	Issuer              *big.Int
}

func (u *updateValues) toList() []*big.Int {
	return []*big.Int{
		u.Address,
		u.Birthday,
		u.Gender,
		u.Name,
		u.ReferenceID,
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
