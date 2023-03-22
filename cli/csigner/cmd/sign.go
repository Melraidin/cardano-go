package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/safanaj/cardano-go/crypto"
	"github.com/safanaj/cardano-go/libsodium"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message using a private/secret key",
	RunE: func(cmd *cobra.Command, args []string) error {
		// useCIP8, _ := cmd.Flags().GetBool("cip8")
		// useCIP30, _ := cmd.Flags().GetBool("cip30")
		useCIP22, _ := cmd.Flags().GetBool("cip22")
		data, _ := cmd.Flags().GetString("data")
		nonce, _ := cmd.Flags().GetString("nonce")

		var sigBytes []byte
		dataHex := hex.EncodeToString([]byte(data))

		prvKeyBytes, useSodium, rerr := getPrivateKey(cmd)
		if rerr != nil {
			return rerr
		}

		if useSodium {
			var seed string
			libsodium.Initialize_libsodium()
			if useCIP22 {
				prefixHex := hex.EncodeToString([]byte("cip-0022"))
				seed = prefixHex + dataHex
			} else {
				seed = dataHex
			}
			if nonce != "" {
				seed = seed + nonce
			}
			seedData, err := hex.DecodeString(seed)
			if err != nil {
				return fmt.Errorf("invalid computed seed, expected valid hex-encoded string: %v", err)
			}

			dataHashBytes := blake2b.Sum256(seedData)
			sigBytes, rerr = libsodium.CryptoVrfProve(prvKeyBytes, dataHashBytes[:])
		} else {
			prvKey := crypto.PrvKey(prvKeyBytes)
			// sigBytes = prvKey.Sign([]byte(dataHex))
			sigBytes = prvKey.Sign([]byte(data))
			fmt.Println("public key: ", prvKey.PubKey().String())
		}
		if rerr == nil {
			fmt.Println("signature: ", hex.EncodeToString(sigBytes))
		} else {
			fmt.Println("failure: ", rerr)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().AddFlagSet(rootCmd.Flags())
	signCmd.Flags().String("vrf-skey-cbor-hex", "", "VRF private key to sign")
	signCmd.Flags().String("secret-key", "", "private key to sign (bech32 or hex)")
	signCmd.Flags().String("secret-key-file", "", "private key file path")
}
