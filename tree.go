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
	newleaf("4809579517396073186705705159186899409599314609122482090560534255195823961763", "3751782318016764902460517383636219429745087389162942693670855676890817944684"),  // credentialSubjectType
	newleaf("1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962"),  // credentialSchemaType
	newleaf("12891444986491254085560597052395677934694594587847693550621945641098238258096", "1173248646377539879946536107369421994820880702773342056419798525241229208349"), // credentialStatusType
	newleaf("14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370"), // typeID1
	newleaf("18943208076435454904128050626016920086499867123501959273334294100443438004188", "3751782318016764902460517383636219429745087389162942693670855676890817944684"), // typeDI2
	newleaf("2282658739689398501857830040602888548545380116161185117921371325237897538551", "7267241749008249664184827982574396251114082060252725574405923105367928296171"),  // credentialSchemaID
}

var updateTemplate = []leaf{
	newleaf("13319952139078733522750695554630631933458346585087910879123048180112892347049", "0"), // birthday
	newleaf("10164804319113601592709052825465566543798059716079261081106678069863727363127", "0"), // gender
	newleaf("1044934786333234750726995748708908396493389234902509278003344567776685904786", "0"),  // pincode
	newleaf("18399736510711010434057702561154623084154073746787114033062223519394499254431", "0"), // state
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
