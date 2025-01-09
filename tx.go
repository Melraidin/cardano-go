package cardano

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/echovl/cardano-go/internal/cbor"

	"github.com/melraidin/cardano-go/crypto"
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

// TxOutput is the transaction output.
type TxOutput struct {
	TxBabbageOutput
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

func (o *TxOutput) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal([]interface{}{o.Address.Bytes(), o.Amount})
}

func (o *TxOutput) UnmarshalCBOR(data []byte) error {
	if o == nil {
		return errors.New("unmarshal to nil output")
	}

	type Raw struct {
		_          struct{} `cbor:",toarray"`
		RawAddress []byte
		RawAmount  cbor.RawMessage
	}
	var raw Raw
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}

	addr, err := NewAddressFromBytes(raw.RawAddress)
	if err != nil {
		return err
	}

	if len(raw.RawAmount) == 0 {
		return errors.New("no raw amount cbor bytes")
	}
	var amount Value
	if err := cbor.Unmarshal(raw.RawAmount, &amount); err != nil {
		return err
	}
	o.Amount = &amount
	o.Address = addr
	return nil
=======
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
>>>>>>> 62f1c00 (added suport for tx output in alonzo and babbage era, close #1)
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

// Hash returns the transaction body hash using blake2b256.
func (body *TxBody) Hash() (Hash32, error) {
	bytes, err := cborEnc.Marshal(body)
	if err != nil {
		return Hash32{}, err
	}
	hash := blake2b.Sum256(bytes)
	return hash[:], nil
}
