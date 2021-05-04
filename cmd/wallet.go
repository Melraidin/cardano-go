/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"strings"

	"github.com/echovl/cardano-wallet/db"
	"github.com/echovl/cardano-wallet/wallet"
	"github.com/spf13/cobra"
)

// walletCmd represents the wallet command
var walletCmd = &cobra.Command{
	Use:   "wallet [wallet-name]",
	Short: "Creates a brand new wallet",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password, _ := cmd.Flags().GetString("password")
		mnemonic, _ := cmd.Flags().GetStringSlice("mnemonic")

		if len(mnemonic) == 0 {
			w, mnemonic, _ := wallet.AddWallet(args[0], password)

			bdb := db.NewBadgerDB()
			bdb.SaveWallet(w)
			defer bdb.Close()

			fmt.Printf("mnemonic: %v\n", mnemonic)
		} else {
			wallet.RestoreWallet(strings.Join(mnemonic, " "), password)
		}
	},
}

func init() {
	newCmd.AddCommand(walletCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// walletCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// walletCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	walletCmd.Flags().StringP("password", "p", "", "Password to create or restore the wallet")
	walletCmd.Flags().StringSliceP("mnemonic", "m", nil, "Mnemonic to restore the wallet")
}