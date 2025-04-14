package template

import (
	"context"
	"fmt"
	"math/big"

	"github.com/0xPolygonID/go-circuit-external/common"
	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

type Template struct {
	tree *merkletree.MerkleTree
}

type Node struct {
	Key   *big.Int
	Value *big.Int
}

func NewNode(key, value string) Node {
	return Node{
		Key:   common.MustBigInt(key),
		Value: common.MustBigInt(value),
	}
}

func NewNodeFromList(nodes []string) []Node {
	result := make([]Node, len(nodes))
	for i, node := range nodes {
		keyValue := common.MustBigInt(node)
		result[i] = Node{
			Key:   keyValue,
			Value: keyValue,
		}
	}
	return result
}

func New(
	level int,
) (*Template, error) {
	treeStorage := memory.NewMemoryStorage()
	mt, err := merkletree.NewMerkleTree(context.Background(), treeStorage, level)
	if err != nil {
		return nil, fmt.Errorf("failed to create merkle tree: %w", err)
	}
	return &Template{mt}, nil

}

func (t *Template) Upload(ctx context.Context, nodes []Node) error {
	for _, node := range nodes {
		err := t.tree.Add(ctx, node.Key, node.Value)
		if err != nil {
			return fmt.Errorf("failed to add node {k: '%s'; v: '%s'} to merkle tree: %w",
				node.Key, node.Value, err)
		}
	}
	return nil
}

func (t *Template) Update(ctx context.Context, nodes []Node) ([][]*big.Int, error) {
	proofs := make([][]*big.Int, 0, len(nodes))
	for _, node := range nodes {
		p, err := t.tree.Update(context.Background(), node.Key, node.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to update node {k: '%s'; v: '%s'} in merkle tree: %w",
				node.Key, node.Value, err)
		}
		if p.Siblings[len(p.Siblings)-1].BigInt().Cmp(big.NewInt(0)) != 0 {
			return nil, fmt.Errorf("last sibling should be 0")
		}

		proofs = append(proofs,
			circuits.PrepareSiblings(p.Siblings[:t.tree.MaxLevels()], t.tree.MaxLevels()))
	}

	return proofs, nil
}

func (t *Template) Root() *big.Int {
	return t.tree.Root().BigInt()
}
