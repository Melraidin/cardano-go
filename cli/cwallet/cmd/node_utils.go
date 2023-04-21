package cmd

import (
	"context"

	"github.com/safanaj/cardano-go"
	"github.com/safanaj/cardano-go/blockfrost"
	"github.com/safanaj/cardano-go/koios"
	"github.com/safanaj/cardano-go/wallet"
)

func getNode(ctx context.Context, n cardano.Network, c Config) cardano.Node {
	if c.UseKoios {
		return koios.NewNode(n, ctx)
	}
	return blockfrost.NewNode(n, c.BlockfrostProjectID)

}

func getClient(ctx context.Context, useTestnet bool, c Config) *wallet.Client {
	network := cardano.Mainnet
	if useTestnet {
		network = cardano.Testnet
	}
	return wallet.NewClient(&wallet.Options{Node: getNode(ctx, network, c)})
}
