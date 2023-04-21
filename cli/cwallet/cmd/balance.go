package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var balanceCmd = &cobra.Command{
	Use:     "balance [wallet]",
	Short:   "Get cardano.s balance",
	Aliases: []string{"bal"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		useTestnet, _ := cmd.Flags().GetBool("testnet")
		client := getClient(cmd.Context(), useTestnet, cfg)
		defer client.Close()

		id := args[0]
		w, err := client.Wallet(id)
		if err != nil {
			return err
		}

		balance, err := w.Balance()
		if err != nil {
			return err
		}
		fmt.Printf("%-25v %-9v\n", "ASSET", "AMOUNT")
		fmt.Printf("%-25v %-9v\n", "Lovelace", balance.Coin)
		for _, pool := range balance.MultiAsset.Keys() {
			for _, assetName := range balance.MultiAsset.Get(pool).Keys() {
				fmt.Printf("%-25v %-9v\n", assetName, balance.MultiAsset.Get(pool).Get(assetName))
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(balanceCmd)
	balanceCmd.Flags().Bool("testnet", false, "Use testnet network")
}
