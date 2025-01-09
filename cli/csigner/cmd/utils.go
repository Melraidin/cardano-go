package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/melraidin/cardano-go"
	"github.com/melraidin/cardano-go/crypto"
	"github.com/melraidin/cardano-go/internal/cbor"
	"github.com/melraidin/cardano-go/libsodium"
	"github.com/spf13/cobra"
)

func getPublicKey(cmd *cobra.Command) ([]byte, bool, error) {
	useSodium := false
	vrfVKeyCborHex, _ := cmd.Flags().GetString("vrf-vkey-cbor-hex")
	pubkey, _ := cmd.Flags().GetString("public-key")
	pubkeyfile, _ := cmd.Flags().GetString("public-key-file")

	var pubKey crypto.PubKey
	if vrfVKeyCborHex != "" {
		useSodium = true
		libsodium.Initialize_libsodium()
		vrfVKeyData, err := cardano.GetBytesFromCBORHex(vrfVKeyCborHex)
		if err != nil {
			return nil, useSodium, err
		}
		return vrfVKeyData, useSodium, nil
	} else if pubkey != "" {
		// try hex
		pubKeyData, err := hex.DecodeString(pubkey)
		if err == nil {
			return pubKeyData, useSodium, nil
		}
		// try bech32
		parts := strings.SplitN(pubkey, "1", 2)
		if strings.HasSuffix(parts[0], "_vk") {
			pubKey, err = crypto.NewPubKey(pubkey)
		} else if strings.HasSuffix(parts[0], "_xvk") {
			pubXKey, err := crypto.NewXPubKey(pubkey)
			if err != nil {
				return nil, useSodium, err
			}
			pubKey = pubXKey.PubKey()
		} else {
			return nil, false, fmt.Errorf("invalid public key, hex or bech32 required")
		}
	} else if pubkeyfile != "" {

		dat, err := os.ReadFile(pubkeyfile)
		if err != nil {
			return nil, useSodium, err
		}

		m := map[string]string{}
		if err = json.Unmarshal(dat, &m); err != nil {
			return nil, useSodium, err
		}

		if strings.HasPrefix(m["type"], "VrfVerificationKey_") {
			useSodium = true
			libsodium.Initialize_libsodium()
			vrfVKeyData, err := cardano.GetBytesFromCBORHex(vrfVKeyCborHex)
			if err != nil {
				return nil, useSodium, err
			}
			return vrfVKeyData, useSodium, nil
		}

		cborData, err := hex.DecodeString(m["cborHex"])
		var pubkeyData []byte
		if err = cbor.Unmarshal(cborData, &pubkeyData); err != nil {
			return nil, useSodium, err
		}

		if strings.Contains(m["type"], "VerificationKey") {
			if strings.Contains(m["type"], "Extended") {
				pubKey = crypto.XPubKey(pubkeyData).PubKey()
			} else {
				pubKey = crypto.PubKey(pubkeyData)
			}
		} else {
			return nil, false, fmt.Errorf("unknown public key format")
		}
	} else {
		return nil, false, fmt.Errorf("missing public key to verify data and signature")
	}
	return []byte(pubKey), useSodium, nil
}

func getPrivateKey(cmd *cobra.Command) ([]byte, bool, error) {
	useSodium := false
	vrfSKeyCborHex, _ := cmd.Flags().GetString("vrf-skey-cbor-hex")
	prvkey, _ := cmd.Flags().GetString("secret-key")
	prvkeyfile, _ := cmd.Flags().GetString("secret-key-file")

	var prvKey crypto.PrvKey
	if vrfSKeyCborHex != "" {
		useSodium = true
		libsodium.Initialize_libsodium()
		vrfSKeyData, err := cardano.GetBytesFromCBORHex(vrfSKeyCborHex)
		if err != nil {
			return nil, useSodium, err
		}
		return vrfSKeyData, useSodium, nil
	} else if prvkey != "" {
		// try hex
		prvKeyData, err := hex.DecodeString(prvkey)
		if err == nil {
			return prvKeyData, useSodium, nil
		}
		// try bech32
		parts := strings.SplitN(prvkey, "1", 2)
		if strings.HasSuffix(parts[0], "_sk") {
			prvKey, err = crypto.NewPrvKey(prvkey)
		} else if strings.HasSuffix(parts[0], "_xsk") {
			prvXKey, err := crypto.NewXPrvKey(prvkey)
			if err != nil {
				return nil, useSodium, err
			}
			prvKey = prvXKey.PrvKey()
		} else {
			return nil, false, fmt.Errorf("invalid private key, hex or bech32 required")
		}
	} else if prvkeyfile != "" {

		dat, err := os.ReadFile(prvkeyfile)
		if err != nil {
			return nil, useSodium, err
		}

		m := map[string]string{}
		if err = json.Unmarshal(dat, &m); err != nil {
			return nil, useSodium, err
		}

		if strings.HasPrefix(m["type"], "VrfSigningKey_") {
			useSodium = true
			libsodium.Initialize_libsodium()
			vrfSKeyData, err := cardano.GetBytesFromCBORHex(m["cborHex"])
			if err != nil {
				return nil, useSodium, err
			}
			return vrfSKeyData, useSodium, nil
		}

		cborData, err := hex.DecodeString(m["cborHex"])
		var prvkeyData []byte
		if err = cbor.Unmarshal(cborData, &prvkeyData); err != nil {
			return nil, useSodium, err
		}

		if strings.Contains(m["type"], "SigningKey") {
			if strings.Contains(m["type"], "Extended") {
				prvKey = crypto.XPrvKey(prvkeyData).PrvKey()
			} else {
				prvKey = crypto.PrvKey(prvkeyData)
			}
		} else {
			return nil, false, fmt.Errorf("unknown public key format")
		}

	} else {
		return nil, false, fmt.Errorf("missing public key to verify data and signature")
	}
	return []byte(prvKey), useSodium, nil
}
