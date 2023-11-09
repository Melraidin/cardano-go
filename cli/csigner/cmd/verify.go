package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"

	coselib "github.com/veraison/go-cose"

	"github.com/safanaj/cardano-go/cose"
	"github.com/safanaj/cardano-go/crypto"
	"github.com/safanaj/cardano-go/libsodium"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature of a message using a public key",
	RunE: func(cmd *cobra.Command, args []string) error {
		// useCIP8, _ := cmd.Flags().GetBool("cip8")
		useCIP30, _ := cmd.Flags().GetBool("cip30")
		useCIP22, _ := cmd.Flags().GetBool("cip22")
		data, _ := cmd.Flags().GetString("data")
		nonce, _ := cmd.Flags().GetString("nonce")
		sig, _ := cmd.Flags().GetString("signature")

		if sig == "" {
			return fmt.Errorf("signature is empty, nothing to verify")
		}
		sigBytes, err := hex.DecodeString(sig)
		if err != nil {
			return fmt.Errorf("invalid signature, expected valid hex-encoded string: %v", err)
		}

		dataHex := hex.EncodeToString([]byte(data))

		pubKeyBytes, useSodium, err := getPublicKey(cmd)
		if err != nil {
			return err
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

			seedData, ierr := hex.DecodeString(seed)
			if ierr != nil {
				return fmt.Errorf("invalid computed seed, expected valid hex-encoded string: %v", ierr)
			}

			dataHashBytes := blake2b.Sum256(seedData)
			_, err = libsodium.CryptoVrfVerify(pubKeyBytes, sigBytes, dataHashBytes[:])
		} else if useCIP30 {

			_ = bytes.Equal
			_ = coselib.HeaderLabelKeyID
			err = cose.VerifyFromCBORHex(sig, hex.EncodeToString(pubKeyBytes))
		} else {
			pubKey := crypto.PubKey(pubKeyBytes)
			if pubKey.Verify([]byte(data), sigBytes) {
				err = nil
			} else {
				err = fmt.Errorf("verify failed")
			}
		}

		if err == nil {
			fmt.Println("success, signature verified")
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().AddFlagSet(rootCmd.Flags())
	verifyCmd.Flags().String("signature", "", "signature of the signed message")
	verifyCmd.Flags().String("vrf-vkey-cbor-hex", "", "VRF public key to sign")
	verifyCmd.Flags().String("public-key", "", "public key to sign (bech32 or hex)")
	verifyCmd.Flags().String("public-key-file", "", "public key file path")
}
