package cmd

import (
	"fmt"
	"strconv"

	"github.com/safanaj/cardano-go"
	"github.com/spf13/cobra"
)

// TODO: Ask for password if present
// Experimental feature, only for testnet
var transferCmd = &cobra.Command{
	Use:   "transfer [wallet] [receiver] [amount]",
	Short: "Transfer an amount of lovelace to the given address",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		useTestnet, _ := cmd.Flags().GetBool("testnet")
		client := getClient(cmd.Context(), useTestnet, cfg)
		defer client.Close()
		senderId := args[0]
		receiver, err := cardano.NewAddress(args[1])
		if err != nil {
			return err
		}
		amount, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			return err
		}
		w, err := client.Wallet(senderId)
		if err != nil {
			return err
		}
		txHash, err := w.Transfer(receiver, cardano.NewValue(cardano.Coin(amount)))
		if err != nil {
			return err
		}
		fmt.Println(txHash)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(transferCmd)
	transferCmd.Flags().Bool("testnet", false, "Use testnet network")
}
