package cardano

import (
	"encoding/hex"
	"fmt"

	cborv2 "github.com/fxamacker/cbor/v2"
	"github.com/melraidin/cardano-go/crypto"
	"github.com/melraidin/cardano-go/internal/cbor"
	"golang.org/x/crypto/blake2b"
)

const utxoEntrySizeWithoutVal = 27

// UTxO is a Cardano Unspent Transaction Output.
type UTxO struct {
	TxHash  Hash32
	Spender Address
	Amount  *Value
	Index   uint64
}

// Tx is a Cardano transaction.
type Tx struct {
	_             struct{} `cbor:",toarray"`
	Body          TxBody
	WitnessSet    WitnessSet
	IsValid       bool
	AuxiliaryData *AuxiliaryData // or null
}

// Bytes returns the CBOR encoding of the transaction as bytes.
func (tx *Tx) Bytes() []byte {
	bytes, err := cborEnc.Marshal(tx)
	if err != nil {
		panic(err)
	}
	return bytes
}

// Hex returns the CBOR encoding of the transaction as hex.
func (tx Tx) Hex() string {
	return hex.EncodeToString(tx.Bytes())
}

// Hash returns the transaction body hash using blake2b.
func (tx *Tx) Hash() (Hash32, error) {
	return tx.Body.Hash()
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (tx *Tx) UnmarshalCBOR(data []byte) error {
	type rawTx Tx
	var rt rawTx

	err := cborDec.Unmarshal(data, &rt)
	if err != nil {
		return err
	}
	tx.Body = rt.Body
	tx.WitnessSet = rt.WitnessSet
	tx.IsValid = rt.IsValid
	tx.AuxiliaryData = rt.AuxiliaryData

	return nil
}

// MarshalCBOR implements cbor.Marshaler.
func (tx *Tx) MarshalCBOR() ([]byte, error) {
	type rawTx Tx
	return cborEnc.Marshal(rawTx(*tx))
}

// WitnessSet represents the witnesses of the transaction.
type WitnessSet struct {
	VKeyWitnessSet []VKeyWitness  `cbor:"0,keyasint,omitempty"`
	Scripts        []NativeScript `cbor:"1,keyasint,omitempty"`
}

// VKeyWitness is a witnesss that uses verification keys.
type VKeyWitness struct {
	_         struct{}      `cbor:",toarray"`
	VKey      crypto.PubKey // ed25519 public key
	Signature []byte        // ed25519 signature
}

// MarshalCBORWrapped wraps the VKeyWitness so that the CBOR structure matches what cardano-cli
// generates when witnessing a transaction.
func (vk *VKeyWitness) MarshalCBORWrapped() ([]byte, error) {
	// It's not clear what the 0 represents in this structure but cardano-cli does it so we
	// do too.
	wrapper := struct {
		_           struct{} `cbor:",toarray"`
		CLIConstant int      `cbor:"0,keyasint"`
		VK          VKeyWitness
	}{
		VK: *vk,
	}
	return cborEnc.Marshal(wrapper)
}

// TxInput is the transaction input.
type TxInput struct {
	_      struct{} `cbor:",toarray"`
	TxHash Hash32
	Index  uint64
	Amount *Value `cbor:"-"`
}

// NewTxInput creates a new instance of TxInput
func NewTxInput(txHash Hash32, index uint, amount *Value) *TxInput {
	return &TxInput{TxHash: txHash, Index: uint64(index), Amount: amount}
}

// String implements stringer.
func (t TxInput) String() string {
	return fmt.Sprintf("{TxHash: %v, Index: %v, Amount: %v}", t.TxHash, t.Index, t.Amount)
}

// DatumType
type DatumType int

const (
	DatumTypeHash DatumType = iota
	DatumTypeData
)

// DatumOption
type DatumOption struct {
	_    struct{} `cbor:",toarray"`
	Type DatumType
	Data []byte
}

func (do *DatumOption) String() string {
	switch do.Type {
	case DatumTypeHash:
		return fmt.Sprintf("(hash: %v)", hex.EncodeToString(do.Data))
	case DatumTypeData:
		return fmt.Sprintf("(data: %v)", do.Data)
	default:
		return fmt.Sprintf("%v", *do)
	}
}

// TxLegacyOutput is the transaction output before alonzo, shelley-mary-allegra.
type TxLegacyOutput struct {
	_       struct{} `cbor:",toarray"`
	Address Address
	Amount  *Value
}

type TxAlonzoOutput struct {
	_         struct{} `cbor:",toarray"`
	Address   Address
	Amount    *Value
	DatumHash []byte `cbor:",omitempty"`
}

// TxBabbageOutput is the transaction output after alonzo, in babbage era.
type TxBabbageOutput struct {
	Address Address `cbor:"0,keyasint"`
	Amount  *Value  `cbor:"1,keyasint"`
	// TODO: double-check/verify if the below 2 fields need double CBOR enc/dec-oding,
	// in the cddl those are tagged as #6.24 , means encoded-cbor
	DatumOption *DatumOption `cbor:"2,keyasint,omitempty"`
	ScriptRef   []byte       `cbor:"3,keyasint,omitempty"`
}

// TxOutput is the transaction output after alonzo, in babbage era.
type TxOutput struct {
	TxBabbageOutput
}

// NewTxOutput creates a new instance of TxOutput
func NewTxOutput(addr Address, amount *Value, extras ...any) *TxOutput {
	txo := &TxOutput{TxBabbageOutput{Address: addr, Amount: amount}}
	if len(extras) > 2 {
		return txo
	} else if len(extras) == 2 {
		// this is a babbage tx output
		if do, ok := extras[0].(*DatumOption); ok {
			txo.DatumOption = do
		}
		if sr, ok := extras[1].([]byte); ok {
			txo.ScriptRef = sr
		}
	} else if len(extras) == 1 {
		// this could be a babbage tx output or an alonzo one, depends on the extra param type
		switch v := extras[0].(type) {
		case []byte:
			// it is an alonzo tx output, this is the datum hash
			txo.DatumOption = &DatumOption{Type: DatumTypeHash, Data: v}
		case *DatumOption:
			txo.DatumOption = v
		}
	}
	return txo
}

func (t *TxOutput) UnmarshalCBOR(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// should we check for arbitrary long container types, like 0xbf (map) or 0x9f (list) ?
	switch data[0] & 0xf0 {
	case 0xa0:
		var rto TxBabbageOutput
		// this is a map, so use babbage era, post alonzo format
		err := cborDec.Unmarshal(data, &rto)
		if err != nil {
			return err
		}

		t.Address = rto.Address
		t.Amount = rto.Amount
		t.DatumOption = rto.DatumOption
		t.ScriptRef = rto.ScriptRef
	case 0x80:
		if (data[0] & 0x0f) == 0x03 {
			var lto TxAlonzoOutput
			err := cborDec.Unmarshal(data, &lto)
			if err != nil {
				return err
			}

			t.Address = lto.Address
			t.Amount = lto.Amount
			if lto.DatumHash != nil {
				t.DatumOption = &DatumOption{Type: DatumTypeHash, Data: lto.DatumHash}
			}
		} else if (data[0] & 0x0f) == 0x02 {
			var lto TxLegacyOutput
			err := cborDec.Unmarshal(data, &lto)
			if err != nil {
				return err
			}
			t.Address = lto.Address
			t.Amount = lto.Amount
		}
	}

	return nil
}

// MarshalCBOR implements cbor.Marshaler.
func (t *TxOutput) MarshalCBOR() ([]byte, error) {
	if t.Address.ByronAddr != nil {
		return cbor.Marshal([]interface{}{t.Address.Bytes(), t.Amount})
	}

	// we want to minimize the output length, so prefer legacy, alonzo, babbage
	if t.ScriptRef != nil {
		// we need full babbage output
		return cborEnc.Marshal(t.TxBabbageOutput)
	}
	if t.DatumOption != nil {
		// we could use babbage or alonzo format
		if t.DatumOption.Type == DatumTypeHash {
			// use alonzo format
			return cborEnc.Marshal(TxAlonzoOutput{
				Address:   t.Address,
				Amount:    t.Amount,
				DatumHash: t.DatumOption.Data,
			})
		}
		return cborEnc.Marshal(t.TxBabbageOutput)
	}
	// just use legacy tx output as we have just address and amount
	return cborEnc.Marshal(TxLegacyOutput{Address: t.Address, Amount: t.Amount})
}

func (t TxOutput) String() string {
	s := fmt.Sprintf("{Address: %v, Amount: %v", t.Address, t.Amount)
	if t.DatumOption != nil {
		s += fmt.Sprintf(", DatumOption: %v", t.DatumOption)
	}
	if t.ScriptRef != nil {
		s += fmt.Sprintf(", ScriptRef: %v", t.ScriptRef)
	}
	s += "}"
	return s
}

type TxBody struct {
	// This is used to store the raw CBOR bytes of the transaction body in case the transaction was
	// generated externally. This allows avoiding issues with unmarshalling and then marshalling
	// again causing changes to the transaction body (e.g., from keys being ordered differently in
	// a map).
	WrappedTxBody []byte `cbor:"-"`

	Inputs  []*TxInput  `cbor:"0,keyasint"`
	Outputs []*TxOutput `cbor:"1,keyasint"`
	Fee     Coin        `cbor:"2,keyasint"`

	// Optionals
	TTL                   Uint64        `cbor:"3,keyasint,omitempty"`
	Certificates          []Certificate `cbor:"4,keyasint,omitempty"`
	Withdrawals           interface{}   `cbor:"5,keyasint,omitempty"` // unsupported
	Update                interface{}   `cbor:"6,keyasint,omitempty"` // unsupported
	AuxiliaryDataHash     *Hash32       `cbor:"7,keyasint,omitempty"`
	ValidityIntervalStart Uint64        `cbor:"8,keyasint,omitempty"`
	Mint                  *Mint         `cbor:"9,keyasint,omitempty"`
	ScriptDataHash        *Hash32       `cbor:"11,keyasint,omitempty"`
	Collateral            []*TxInput    `cbor:"13,keyasint,omitempty"`
	RequiredSigners       []AddrKeyHash `cbor:"14,keyasint,omitempty"`
	NetworkID             Uint64        `cbor:"15,keyasint,omitempty"`
	CollateralReturn      *TxOutput     `cbor:"16,keyasint,omitempty"`
	TotalCollateral       Coin          `cbor:"17,keyasint,omitempty"`
	ReferenceInputs       []*TxInput    `cbor:"18,keyasint,omitempty"`
}

// MarshalCBOR implements cbor.Marshaler for TxBody.
// It applies CBOR tag 258 to the Inputs array to match cardano-cli output format.
func (body *TxBody) MarshalCBOR() ([]byte, error) {
	// Create a custom structure that will be marshaled with the tagged inputs
	type taggedTxBody struct {
		Inputs                cbor.Tag      `cbor:"0,keyasint"`
		Outputs               []*TxOutput   `cbor:"1,keyasint"`
		Fee                   Coin          `cbor:"2,keyasint"`
		TTL                   Uint64        `cbor:"3,keyasint,omitempty"`
		Certificates          []Certificate `cbor:"4,keyasint,omitempty"`
		Withdrawals           interface{}   `cbor:"5,keyasint,omitempty"`
		Update                interface{}   `cbor:"6,keyasint,omitempty"`
		AuxiliaryDataHash     *Hash32       `cbor:"7,keyasint,omitempty"`
		ValidityIntervalStart Uint64        `cbor:"8,keyasint,omitempty"`
		Mint                  *Mint         `cbor:"9,keyasint,omitempty"`
		ScriptDataHash        *Hash32       `cbor:"11,keyasint,omitempty"`
		Collateral            []*TxInput    `cbor:"13,keyasint,omitempty"`
		RequiredSigners       []AddrKeyHash `cbor:"14,keyasint,omitempty"`
		NetworkID             Uint64        `cbor:"15,keyasint,omitempty"`
		CollateralReturn      *TxOutput     `cbor:"16,keyasint,omitempty"`
		TotalCollateral       Coin          `cbor:"17,keyasint,omitempty"`
		ReferenceInputs       []*TxInput    `cbor:"18,keyasint,omitempty"`
	}

	// Create the tagged structure with tag 258 for Inputs
	tagged := taggedTxBody{
		Inputs: cbor.Tag{
			Number:  258,
			Content: body.Inputs,
		},
		Outputs:               body.Outputs,
		Fee:                   body.Fee,
		TTL:                   body.TTL,
		Certificates:          body.Certificates,
		Withdrawals:           body.Withdrawals,
		Update:                body.Update,
		AuxiliaryDataHash:     body.AuxiliaryDataHash,
		ValidityIntervalStart: body.ValidityIntervalStart,
		Mint:                  body.Mint,
		ScriptDataHash:        body.ScriptDataHash,
		Collateral:            body.Collateral,
		RequiredSigners:       body.RequiredSigners,
		NetworkID:             body.NetworkID,
		CollateralReturn:      body.CollateralReturn,
		TotalCollateral:       body.TotalCollateral,
		ReferenceInputs:       body.ReferenceInputs,
	}

	return cborEnc.Marshal(tagged)
}

// FirstElemRaw returns the raw CBOR bytes of the first element
// of a CBOR-encoded array, without re-marshaling.
func FirstElemRaw(cborData []byte) ([]byte, error) {
	var elems []cbor.RawMessage
	if err := cborv2.Unmarshal(cborData, &elems); err != nil {
		return nil, fmt.Errorf("decode array: %w", err)
	}
	if len(elems) == 0 {
		return nil, fmt.Errorf("empty CBOR array")
	}

	return elems[0], nil
}

// Hash returns the transaction body hash using blake2b256.
func (body *TxBody) Hash() (Hash32, error) {
	if len(body.WrappedTxBody) != 0 {
		// The actual transaction body is the first element in the wrapped body. This allows us to
		// avoid unmarshalling the transaction body, leaving it as just a byte slice.
		rawTxBody, err := FirstElemRaw(body.WrappedTxBody)
		if err != nil {
			return Hash32{}, fmt.Errorf("failed to get first element raw: %w", err)
		}

		hash := blake2b.Sum256(rawTxBody)
		return hash[:], nil
	}

	bytes, err := cborEnc.Marshal(body)
	if err != nil {
		return Hash32{}, err
	}
	hash := blake2b.Sum256(bytes)
	return hash[:], nil
}
