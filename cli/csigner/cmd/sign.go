package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/melraidin/cardano-go"
	"github.com/melraidin/cardano-go/cose"
	"github.com/melraidin/cardano-go/crypto"
	"github.com/melraidin/cardano-go/libsodium"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message using a private/secret key",
	RunE: func(cmd *cobra.Command, args []string) error {
		// useCIP8, _ := cmd.Flags().GetBool("cip8")
		useCIP30, _ := cmd.Flags().GetBool("cip30")
		useCIP22, _ := cmd.Flags().GetBool("cip22")
		data, _ := cmd.Flags().GetString("data")
		nonce, _ := cmd.Flags().GetString("nonce")
		outJson, _ := cmd.Flags().GetBool("json")

		var (
			outPubKey, outSignature string
		)

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

			pubKey, err := libsodium.CryptoVrfPublicKeyFromSecretKey(prvKeyBytes)
			if err != nil {
				return fmt.Errorf("invalid private key: %v", err)
			}
			pubKeyCBORHex, err := cardano.GetCBORHexFromBytes(pubKey)
			if err != nil {
				return fmt.Errorf("internal error: %v", err)
			}

			dataHashBytes := blake2b.Sum256(seedData)
			sigBytes, rerr = libsodium.CryptoVrfProve(prvKeyBytes, dataHashBytes[:])
			outPubKey = pubKeyCBORHex
		} else if useCIP30 {
			prvKey := crypto.PrvKey(prvKeyBytes)
			kid, err := prvKey.PubKey().Hash()
			if err != nil {
				return fmt.Errorf("invalid private key: %v", err)
			}
			cosePrvKey, err := cose.NewCOSEKeyFromBytes(prvKeyBytes)
			if err != nil {
				return fmt.Errorf("invalid private key: %v", err)
			}
			cosePubKey, err := cose.NewCOSEKeyFromBytes(crypto.PrvKey(cosePrvKey.Key.Bytes()).PubKey())
			if err != nil {
				return fmt.Errorf("invalid private key: %v", err)
			}
			signer, err := cose.NewExtendedSignerFromCOSEKey(cosePrvKey)
			if err != nil {
				return fmt.Errorf("invalid private key: %v", err)
			}
			outPubKeyBytes, err := cosePubKey.MarshalCBOR()
			if err != nil {
				return fmt.Errorf("invalid private key: %v", err)
			}
			_ = kid
			msgToSign := cose.NewCOSESign1MessageWithPayload(data, nil /* kid */)
			err = msgToSign.Sign(nil, nil, signer)
			if err != nil {
				return fmt.Errorf("unable to sign: %v", err)
			}
			sigBytes, rerr = msgToSign.MarshalCBOR()
			outPubKey = hex.EncodeToString(outPubKeyBytes)

		} else {
			prvKey := crypto.PrvKey(prvKeyBytes)
			sigBytes = prvKey.Sign([]byte(data))
			outPubKey = prvKey.PubKey().String()
		}

		outSignature = hex.EncodeToString(sigBytes)
		if rerr == nil {
			if !outJson {
				fmt.Println("public key: ", outPubKey)
				fmt.Println("signature: ", outSignature)
			} else {
				out, _ := json.MarshalIndent(map[string]string{
					"publicKey": outPubKey, "signature": outSignature,
				}, "", "  ")
				fmt.Println(string(out))
			}
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
