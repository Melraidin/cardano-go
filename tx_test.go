package cardano

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/melraidin/cardano-go/crypto"
	"github.com/melraidin/cardano-go/internal/cbor"
)

func TestTxEncoding(t *testing.T) {
	txBuilder := NewTxBuilder(alonzoProtocol)

	paymentKey := crypto.NewXPrvKeyFromEntropy([]byte("payment"), "")
	policyKey := crypto.NewXPrvKeyFromEntropy([]byte("policy"), "")

	txHash, err := NewHash32("030858db80bf94041b7b1c6fbc0754a9bd7113ec9025b1157a9a4e02135f3518")
	if err != nil {
		t.Fatal(err)
	}
	addr, err := NewAddress("addr_test1vp9uhllavnhwc6m6422szvrtq3eerhleer4eyu00rmx8u6c42z3v8")
	if err != nil {
		t.Fatal(err)
	}

	policyScript, err := NewScriptPubKey(policyKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := NewPolicyID(policyScript)
	if err != nil {
		t.Fatal(err)
	}

	inputAmount, transferAmount, assetAmount := Coin(1e9), Coin(10e6), int64(1e9)

	assetName := NewAssetName("cardanogo")
	newAsset := NewMint().
		Set(
			policyID,
			NewMintAssets().
				Set(assetName, big.NewInt(assetAmount)),
		)

	txBuilder.AddInputs(
		NewTxInput(txHash, 0, NewValue(inputAmount)),
	)
	txBuilder.AddOutputs(
		NewTxOutput(addr, NewValueWithAssets(transferAmount, newAsset.MultiAsset())),
	)

	txBuilder.Mint(newAsset)
	txBuilder.AddNativeScript(policyScript)
	txBuilder.SetTTL(100000)
	txBuilder.Sign(paymentKey.PrvKey())
	txBuilder.Sign(policyKey.PrvKey())
	txBuilder.AddChangeIfNeeded(addr)
	txBuilder.AddAuxiliaryData(&AuxiliaryData{
		Metadata: Metadata{
			0: map[interface{}]interface{}{
				"secret": "1234",
				"values": uint64(10),
			},
		},
	})

	gotTx := &Tx{}
	wantTx, err := txBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}

	txBytes, err := wantTx.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	err = gotTx.UnmarshalCBOR(txBytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, txInput := range wantTx.Body.Inputs {
		txInput.Amount = nil
	}

	if !reflect.DeepEqual(wantTx, gotTx) {
		t.Errorf("invalid tx body encoding:\ngot: %+v\nwant: %+v", gotTx, wantTx)
	}
}

func TestCertificateEncoding(t *testing.T) {
	testcases := []struct {
		name    string
		cborHex string
		output  Certificate
	}{
		{
			name:    "StakeRegistration",
			cborHex: "82008200581cd4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b",
			output: Certificate{
				Type: StakeRegistration,
				StakeCredential: StakeCredential{
					Type: KeyCredential,
					KeyHash: AddrKeyHash{
						0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd, 0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6,
						0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2, 0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
					},
				},
			},
		},
		{
			name:    "StakeDeregistration",
			cborHex: "82018200581cd4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b",
			output: Certificate{
				Type: StakeDeregistration,
				StakeCredential: StakeCredential{
					Type: KeyCredential,
					KeyHash: AddrKeyHash{
						0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd, 0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6,
						0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2, 0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
					},
				},
			},
		},
		{
			name:    "StakeDelegation",
			cborHex: "83028200581cd4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b581c20df8645abddf09403ba2656cda7da2cd163973a5e439c6e43dcbea9",
			output: Certificate{
				Type: StakeDelegation,
				StakeCredential: StakeCredential{
					Type: KeyCredential,
					KeyHash: AddrKeyHash{
						0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd, 0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6,
						0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2, 0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
					},
				},
				PoolKeyHash: PoolKeyHash{
					0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x3, 0xba, 0x26, 0x56, 0xcd, 0xa7,
					0xda, 0x2c, 0xd1, 0x63, 0x97, 0x3a, 0x5e, 0x43, 0x9c, 0x6e, 0x43, 0xdc, 0xbe, 0xa9,
				},
			},
		},
		// {
		// 	name:    "PoolRegistration",
		// 	cborHex: "8903581c20df8645abddf09403ba2656cda7da2cd163973a5e439c6e43dcbea9582020df8645abddf09420df8645abddf09420df8645abddf09420df8645abddf0941a001e8480d81e8218230a583901c02e6b0ecdb6bba825ff1fc1e46533c715d5641dccf18cbe06b673e4d4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b81581cd4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b818400190bb844040404045008080808080808080808080808080808f6",
		// 	output: Certificate{
		// 		Type: PoolRegistration,
		// 		Operator: types.PoolKeyHash{
		// 			0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x3, 0xba, 0x26, 0x56, 0xcd, 0xa7,
		// 			0xda, 0x2c, 0xd1, 0x63, 0x97, 0x3a, 0x5e, 0x43, 0x9c, 0x6e, 0x43, 0xdc, 0xbe, 0xa9,
		// 		},
		// 		VrfKeyHash: types.Hash32{
		// 			0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94,
		// 			0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94,
		// 		},
		// 		Pledge: 2000000,
		// 		Margin: types.RationalNumber{P: 35, Q: 10},
		// 		RewardAccount: types.Address{
		// 			B: []byte{
		// 				0x1, 0xc0, 0x2e, 0x6b, 0xe, 0xcd, 0xb6, 0xbb, 0xa8, 0x25, 0xff, 0x1f,
		// 				0xc1, 0xe4, 0x65, 0x33, 0xc7, 0x15, 0xd5, 0x64, 0x1d, 0xcc, 0xf1, 0x8c,
		// 				0xbe, 0x6, 0xb6, 0x73, 0xe4, 0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd,
		// 				0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6, 0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2,
		// 				0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
		// 			},
		// 			Hrp: "addr",
		// 		},
		// 		Owners: []types.AddrKeyHash{
		// 			{
		// 				0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd, 0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6,
		// 				0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2, 0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
		// 			},
		// 		},
		// 		Relays: []Relay{
		// 			{
		// 				Type: SingleHostAddr,
		// 				Port: types.NewUint64(3000),
		// 				Ipv4: []byte{4, 4, 4, 4},
		// 				Ipv6: []byte{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		// 			},
		// 		},
		// 	},
		// },
		{
			name:    "PoolRetirement",
			cborHex: "8304581c20df8645abddf09403ba2656cda7da2cd163973a5e439c6e43dcbea919012c",
			output: Certificate{
				Type: PoolRetirement,
				PoolKeyHash: PoolKeyHash{
					0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x3, 0xba, 0x26, 0x56, 0xcd, 0xa7,
					0xda, 0x2c, 0xd1, 0x63, 0x97, 0x3a, 0x5e, 0x43, 0x9c, 0x6e, 0x43, 0xdc, 0xbe, 0xa9,
				},
				Epoch: 300,
			},
		},
		{
			name:    "GenesisKeyDelegation",
			cborHex: "8405581c20df8645abddf09403ba2656cda7da2cd163973a5e439c6e43dcbea9581c20df8645abddf09403ba2656cda7da2cd163973a5e439c6e43dcbea9582020df8645abddf09420df8645abddf09420df8645abddf09420df8645abddf094",
			output: Certificate{
				Type: GenesisKeyDelegation,
				GenesisHash: Hash28{
					0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x3, 0xba, 0x26, 0x56, 0xcd, 0xa7,
					0xda, 0x2c, 0xd1, 0x63, 0x97, 0x3a, 0x5e, 0x43, 0x9c, 0x6e, 0x43, 0xdc, 0xbe, 0xa9,
				},
				GenesisDelegateHash: Hash28{
					0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x3, 0xba, 0x26, 0x56, 0xcd, 0xa7,
					0xda, 0x2c, 0xd1, 0x63, 0x97, 0x3a, 0x5e, 0x43, 0x9c, 0x6e, 0x43, 0xdc, 0xbe, 0xa9,
				},
				VrfKeyHash: Hash32{
					0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94,
					0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94, 0x20, 0xdf, 0x86, 0x45, 0xab, 0xdd, 0xf0, 0x94,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.cborHex)
			if err != nil {
				t.Fatal(err)
			}

			var cert Certificate
			if err := cbor.Unmarshal(data, &cert); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(cert, tc.output) {
				t.Errorf("got: %+v\nwant: %+v", cert, tc.output)
			}

			rb, err := cbor.Marshal(tc.output)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(rb, data) {
				t.Errorf("got: %v\nwant: %v", rb, data)
			}
		})
	}
}

func TestStakeCredentialEncoding(t *testing.T) {
	testcases := []struct {
		name    string
		cborHex string
		output  StakeCredential
	}{
		{
			name:    "AddrKey",
			cborHex: "8200581cd4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b",
			output: StakeCredential{
				Type: KeyCredential,
				KeyHash: AddrKeyHash{
					0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd, 0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6,
					0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2, 0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
				},
			},
		},
		{
			name:    "ScriptHash",
			cborHex: "8201581cd4ffa2b8832507dd670bccff5ec67901737af9dfb2a277d1cf13302b",
			output: StakeCredential{
				Type: ScriptCredential,
				ScriptHash: Hash28{
					0xd4, 0xff, 0xa2, 0xb8, 0x83, 0x25, 0x7, 0xdd, 0x67, 0xb, 0xcc, 0xff, 0x5e, 0xc6,
					0x79, 0x1, 0x73, 0x7a, 0xf9, 0xdf, 0xb2, 0xa2, 0x77, 0xd1, 0xcf, 0x13, 0x30, 0x2b,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.cborHex)
			if err != nil {
				t.Fatal(err)
			}

			var cred StakeCredential
			if err := cbor.Unmarshal(data, &cred); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(cred, tc.output) {
				t.Errorf("got: %+v\nwant: %+v", cred, tc.output)
			}

			rb, err := cbor.Marshal(tc.output)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(rb, data) {
				t.Errorf("got: %v\nwant: %v", rb, data)
			}
		})
	}
}

func TestRelayEncoding(t *testing.T) {
	testcases := []struct {
		name    string
		cborHex string
		output  Relay
	}{
		{
			name:    "SingleHostAddr",
			cborHex: "8400190bb844040404045008080808080808080808080808080808",
			output: Relay{
				Type: SingleHostAddr,
				Port: NewUint64(3000),
				Ipv4: []byte{4, 4, 4, 4},
				Ipv6: []byte{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
			},
		},
		{
			name:    "SingleHostName",
			cborHex: "8301190bb863646e73",
			output: Relay{
				Type:    SingleHostName,
				Port:    NewUint64(3000),
				DNSName: "dns",
			},
		},
		{
			name:    "MultiHostName",
			cborHex: "820263646e73",
			output: Relay{
				Type:    MultiHostName,
				DNSName: "dns",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.cborHex)
			if err != nil {
				t.Fatal(err)
			}

			var r Relay
			if err := cbor.Unmarshal(data, &r); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(r, tc.output) {
				t.Errorf("got: %+v\nwant: %+v", r, tc.output)
			}

			rb, err := cbor.Marshal(tc.output)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(rb, data) {
				t.Errorf("got: %v\nwant: %v", rb, data)
			}
		})
	}
}

func TestTxDecoding(t *testing.T) {
	// Babbage era, use post alonzo format
	txCborHex := "84a50082825820b3578db07b274dd8d81012a16abe67f55f7d1698f1485623f5a5f46e3a93d40b018258202e01017ba4b9423f4bf55bc9ffbba26f1a5169e1fbef762ea923e730da4b037b000185a300583911d3f00c944c02e92d01373ba8401a0845ad9b2b98df54ad826c5858a25ea481523030b23a495286ca1a18bd141a493e9b5a19d889953f6cdb01821a002e0928a1581cfca746f58adf9f3da13b7227e5e2c6052f376447473f4d49f8004195a151000643b0436974697a656e20233834353401028201d81859019dd87983a7446e616d654d436974697a656e202338343534446f70656e4566616c73654566696c657382a3437372635835697066733a2f2f516d5842755158696a4450776a626853486d5a57454659534231576f46563171706e634d4d634170544553703148446e616d654d436974697a656e202338343534496d656469615479706549696d6167652f676966a3437372635835697066733a2f2f516d614843753641696f73484734697674456a665a6378684b7062464b7833384c64784758366750794d7477486b446e616d654850617373706f7274496d656469615479706549766964656f2f6d703445696d6167655835697066733a2f2f516d5842755158696a4450776a626853486d5a57454659534231576f46563171706e634d4d63417054455370314846476f6c64656e4566616c7365467374616d7073427b7d496d656469615479706549696d6167652f67696601d879860181581ce36f43a40751c35295b19a218301cc7be019d016e8927c0321fd28c7d87a80581cfca746f58adf9f3da13b7227e5e2c6052f376447473f4d49f8004195d87a80d87a80825839019f2c5d54d9cf8466e0109aec09ea58a5060fd75fcaf463cde64d08cd9e81f619476906491b519e3805c0e67e6ccaa6516052b7842d9081f21a11f4b5d082583901dfcb5f6c42f7529f31be82e0e68a75c2db94e425409770341011ef805ea481523030b23a495286ca1a18bd141a493e9b5a19d889953f6cdb1a008583b082583901dfd0594ef1f0f093e16a1c63f7cf76aeab68728b037d6a0945ff5fad2f4ad699c92ce6d1991dd05b64b6275dc3b714641db2b09cffefc830821a0012378ea1581cfca746f58adf9f3da13b7227e5e2c6052f376447473f4d49f8004195a151000de140436974697a656e2023383435340182583901dfd0594ef1f0f093e16a1c63f7cf76aeab68728b037d6a0945ff5fad2f4ad699c92ce6d1991dd05b64b6275dc3b714641db2b09cffefc8301a04caebbc021a00034201031a0536522109a1581cfca746f58adf9f3da13b7227e5e2c6052f376447473f4d49f8004195a251000643b0436974697a656e2023383435340151000de140436974697a656e20233834353401a0f5f6"
	txCborBytes, _ := hex.DecodeString(txCborHex)
	tx := &Tx{}
	err := cbor.Unmarshal(txCborBytes, &tx)
	if err != nil {
		t.Fatal(err)
	}

	// just some checks
	if len(tx.Body.Inputs) != 2 {
		t.Errorf("got: %d inputs\nwant: 2", len(tx.Body.Inputs))
	}
	if len(tx.Body.Outputs) != 5 {
		t.Errorf("got: %d outputs\nwant: 5", len(tx.Body.Outputs))
	}

	if tx.Body.Outputs[0].DatumOption == nil {
		t.Error("got: nil datum on first output\nwant: an inline datum")
	}

	if tx.Body.Outputs[0].DatumOption.Type != DatumTypeData {
		t.Error("got: datum hash on first output\nwant: an inline datum")
	}

	if tx.Body.Fee != Coin(213505) {
		t.Errorf("got: %d as fee\nwant: 213505", tx.Body.Fee)
	}
}

func TestVKeyWitnessMarshalCBORWrapped(t *testing.T) {
	// Create a test VKeyWitness
	testPubKey := crypto.PubKey([]byte("test_public_key_32_bytes_long"))
	testSignature := []byte("test_signature_64_bytes_long_")

	vkeyWitness := VKeyWitness{
		VKey:      testPubKey,
		Signature: testSignature,
	}

	// Marshal the VKeyWitness using the wrapped MarshalCBOR function
	marshaled, err := vkeyWitness.MarshalCBORWrapped()
	if err != nil {
		t.Fatalf("Failed to marshal VKeyWitness: %v", err)
	}

	// Verify that the marshaled data is not empty
	if len(marshaled) == 0 {
		t.Fatal("Marshaled VKeyWitness is empty")
	}

	// Try to unmarshal the data to verify it's valid CBOR
	// The wrapper structure matches what MarshalCBORWrapped creates
	var wrapper struct {
		_           struct{} `cbor:",toarray"`
		CLIConstant int      `cbor:"0,keyasint"`
		VK          VKeyWitness
	}

	err = cbor.Unmarshal(marshaled, &wrapper)
	if err != nil {
		t.Fatalf("Failed to unmarshal VKeyWitness wrapper: %v", err)
	}

	// Verify that the CLIConstant is 0 (as per the implementation)
	if wrapper.CLIConstant != 0 {
		t.Errorf("CLIConstant mismatch: got %d, want 0", wrapper.CLIConstant)
	}

	// Verify that the unmarshaled VKeyWitness matches the original
	unmarshaledWitness := wrapper.VK
	if !reflect.DeepEqual(unmarshaledWitness.VKey, testPubKey) {
		t.Errorf("VKey mismatch: got %v, want %v", unmarshaledWitness.VKey, testPubKey)
	}
	if !reflect.DeepEqual(unmarshaledWitness.Signature, testSignature) {
		t.Errorf("Signature mismatch: got %v, want %v", unmarshaledWitness.Signature, testSignature)
	}

	t.Logf("Successfully marshaled and unmarshaled VKeyWitness wrapped in CLI-compatible structure")
	t.Logf("Marshaled size: %d bytes", len(marshaled))

	// Additional verification: check that the CBOR structure is correct
	// The expected structure is: [0, [vkey, signature]] where 0 is the CLIConstant
	// and the second element is the VKeyWitness array
	var rawData []interface{}
	err = cbor.Unmarshal(marshaled, &rawData)
	if err != nil {
		t.Fatalf("Failed to unmarshal as raw CBOR: %v", err)
	}

	if len(rawData) != 2 {
		t.Fatalf("Expected 2 elements in CBOR array, got %d", len(rawData))
	}

	// First element should be 0 (CLIConstant)
	if cliConstant, ok := rawData[0].(uint64); !ok || cliConstant != 0 {
		t.Errorf("Expected first element to be 0, got %v", rawData[0])
	}

	// Second element should be the VKeyWitness array
	if vkWitnessArray, ok := rawData[1].([]interface{}); !ok || len(vkWitnessArray) != 2 {
		t.Errorf("Expected second element to be VKeyWitness array with 2 elements, got %v", rawData[1])
	}
}

func TestTxBodyMarshalCBORWithTag258(t *testing.T) {
	// Create a simple TxBody with one input
	txHash, err := NewHash32("030858db80bf94041b7b1c6fbc0754a9bd7113ec9025b1157a9a4e02135f3518")
	if err != nil {
		t.Fatal(err)
	}

	addr, err := NewAddress("addr_test1vp9uhllavnhwc6m6422szvrtq3eerhleer4eyu00rmx8u6c42z3v8")
	if err != nil {
		t.Fatal(err)
	}

	txBody := &TxBody{
		Inputs: []*TxInput{
			NewTxInput(txHash, 0, NewValue(1000000)),
		},
		Outputs: []*TxOutput{
			NewTxOutput(addr, NewValue(900000)),
		},
		Fee: 100000,
	}

	// Marshal the TxBody to CBOR
	cborBytes, err := txBody.MarshalCBOR()
	if err != nil {
		t.Fatalf("Failed to marshal TxBody: %v", err)
	}

	// Convert to hex for inspection
	cborHex := hex.EncodeToString(cborBytes)
	t.Logf("TxBody CBOR hex: %s", cborHex)

	// The CBOR should start with tag 258 (d90102) for the Inputs array
	// Expected format: a300d90102818258... where:
	// a3 = map with 3 elements
	// 00 = key 0 (Inputs)
	// d90102 = tag 258
	// 818258... = the actual input array
	if len(cborHex) < 8 {
		t.Fatalf("CBOR too short: %s", cborHex)
	}

	// Check that the Inputs field (key 0) is followed by tag 258
	inputsKeyIndex := strings.Index(cborHex, "00")
	if inputsKeyIndex == -1 {
		t.Fatalf("Could not find Inputs key (00) in CBOR: %s", cborHex)
	}

	// The tag 258 should appear after the key
	tag258Index := strings.Index(cborHex[inputsKeyIndex:], "d90102")
	if tag258Index == -1 {
		t.Fatalf("Could not find tag 258 (d90102) after Inputs key in CBOR: %s", cborHex)
	}

	t.Logf("Successfully verified CBOR tag 258 is applied to Inputs array")
	t.Logf("Tag 258 found at position %d after Inputs key", tag258Index)

	// Verify we can unmarshal the tagged CBOR back to a TxBody
	var unmarshaledBody TxBody
	err = cbor.Unmarshal(cborBytes, &unmarshaledBody)
	if err != nil {
		t.Fatalf("Failed to unmarshal tagged CBOR back to TxBody: %v", err)
	}

	// Verify the unmarshaled data matches the original
	if len(unmarshaledBody.Inputs) != len(txBody.Inputs) {
		t.Errorf("Inputs count mismatch: got %d, want %d", len(unmarshaledBody.Inputs), len(txBody.Inputs))
	}
	if len(unmarshaledBody.Outputs) != len(txBody.Outputs) {
		t.Errorf("Outputs count mismatch: got %d, want %d", len(unmarshaledBody.Outputs), len(txBody.Outputs))
	}
	if unmarshaledBody.Fee != txBody.Fee {
		t.Errorf("Fee mismatch: got %d, want %d", unmarshaledBody.Fee, txBody.Fee)
	}
}
