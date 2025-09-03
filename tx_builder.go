package cardano

import (
	"fmt"
	"math"

	"github.com/melraidin/cardano-go/crypto"
	"golang.org/x/crypto/blake2b"
)

// TxBuilder is a transaction builder.
type TxBuilder struct {
	tx       *Tx
	protocol *ProtocolParams
	pkeys    []crypto.PrvKey

	changeReceiver *Address

	additionalWitnesses uint
	additionalFee       Coin
}

// NewTxBuilder returns a new instance of TxBuilder.
func NewTxBuilder(protocol *ProtocolParams) *TxBuilder {
	return &TxBuilder{
		protocol: protocol,
		pkeys:    []crypto.PrvKey{},
		tx: &Tx{
			IsValid: true,
		},
	}
}

func NewTxBuilderFromTransaction(protocol *ProtocolParams, inputTx *Tx) *TxBuilder {
	return &TxBuilder{
		protocol: protocol,
		pkeys:    []crypto.PrvKey{},
		tx:       inputTx,
	}
}

// AddInputs adds inputs to the transaction.
func (tb *TxBuilder) AddInputs(inputs ...*TxInput) {
	tb.tx.Body.Inputs = append(tb.tx.Body.Inputs, inputs...)
}

// AddOutputs adds outputs to the transaction.
func (tb *TxBuilder) AddOutputs(outputs ...*TxOutput) {
	tb.tx.Body.Outputs = append(tb.tx.Body.Outputs, outputs...)
}

// SetTtl sets the transaction's time to live.
func (tb *TxBuilder) SetTTL(ttl uint64) {
	tb.tx.Body.TTL = NewUint64(ttl)
}

// SetFee sets the transactions's fee.
func (tb *TxBuilder) SetFee(fee Coin) {
	tb.tx.Body.Fee = fee
}

// SetAdditionalWitnesses sets future witnesses for a partially signed transction.
// This is useful to compute the real length and so fee in advance
func (tb *TxBuilder) SetAdditionalWitnesses(witnesses uint) {
	tb.additionalWitnesses = witnesses
}

// SetAdditionalFee sets arbitrary additional fee coins, like a tip or amount to burn.
// This is useful to allow workaround around the auto computation of the minimal fee
func (tb *TxBuilder) SetAdditionalFee(additionalFee Coin) {
	tb.additionalFee = additionalFee
}

// AddAuxiliaryData adds auxiliary data to the transaction.
func (tb *TxBuilder) AddAuxiliaryData(data *AuxiliaryData) {
	tb.tx.AuxiliaryData = data
}

// AddCertificate adds a certificate to the transaction.
func (tb *TxBuilder) AddCertificate(cert Certificate) {
	tb.tx.Body.Certificates = append(tb.tx.Body.Certificates, cert)
}

// AddNativeScript adds a native script to the transaction.
func (tb *TxBuilder) AddNativeScript(script NativeScript) {
	tb.tx.WitnessSet.Scripts = append(tb.tx.WitnessSet.Scripts, script)
}

// Mint adds a new multiasset to mint.
func (tb *TxBuilder) Mint(asset *Mint) {
	tb.tx.Body.Mint = asset
}

// AddChangeIfNeeded instructs the builder to calculate the required fee for the
// transaction and to add an aditional output for the change if there is any.
func (tb *TxBuilder) AddChangeIfNeeded(changeAddr Address) {
	tb.changeReceiver = &changeAddr
}

func (tb *TxBuilder) calculateAmounts() (*Value, *Value) {
	input, output := NewValue(0), NewValue(tb.totalDeposits())
	for _, in := range tb.tx.Body.Inputs {
		if in.Amount != nil {
			input = input.Add(in.Amount)
		}
	}
	for _, out := range tb.tx.Body.Outputs {
		output = output.Add(out.Amount)
	}
	if tb.tx.Body.Mint != nil {
		input = input.Add(NewValueWithAssets(0, tb.tx.Body.Mint.MultiAsset()))
	}
	return input, output
}

func (tb *TxBuilder) totalDeposits() Coin {
	certs := tb.tx.Body.Certificates
	var deposit Coin
	if len(certs) != 0 {
		for _, cert := range certs {
			if cert.Type == StakeRegistration {
				deposit += tb.protocol.KeyDeposit
			}
		}
	}
	return deposit
}

// MinFee computes the minimal fee required for the transaction.
// This assumes that the inputs-outputs are defined and signing keys are present.
func (tb *TxBuilder) MinFee() (Coin, error) {
	// Set a temporary realistic fee in order to serialize a valid transaction
	currentFee := tb.tx.Body.Fee
	tb.tx.Body.Fee = 200000
	if err := tb.build(); err != nil {
		return 0, err
	}
	minFee := tb.calculateMinFee()
	tb.tx.Body.Fee = currentFee
	return minFee, nil
}

// MinCoinsForTxOut computes the minimal amount of coins required for a given transaction output.
// More info could be found in
// <https://github.com/input-output-hk/cardano-ledger/blob/master/doc/explanations/min-utxo-alonzo.rst>
func (tb *TxBuilder) MinCoinsForTxOut(txOut *TxOutput) Coin {
	if txOut == nil {
		return Coin(0)
	}

	data, _ := cborEnc.Marshal(txOut)
	//fmt.Println(err, len(b))
	return Coin(160 + len(data) ) * tb.protocol.CoinsPerUTXOWord
}

// Calculate minimum lovelace a transaction output needs to hold post alonzo.
// This implementation is copied from the origianl Haskell implementation:
// https://github.com/input-output-hk/cardano-ledger/blob/eb053066c1d3bb51fb05978eeeab88afc0b049b2/eras/babbage/impl/src/Cardano/Ledger/Babbage/Rules/Utxo.hs#L242-L265
// TODO:

// calculateMinFee computes the minimal fee required for the transaction.
func (tb *TxBuilder) calculateMinFee() Coin {
	// checking for additionalWitnesses we gonna add fake/empty VKeyWitnesses just to guess the future length and so cost/fee
	if tb.additionalWitnesses > 0 {
		// we can assume the list of VKeyWitnessSet is not a nil value, as `build()` method is always allocating a slice
		additionalVKeyWitnessSet := make([]VKeyWitness, tb.additionalWitnesses)
		for i := uint(0); i < tb.additionalWitnesses; i++ {
			additionalVKeyWitnessSet[i] = VKeyWitness{
				VKey:      crypto.PubKey(make([]byte, 32)),
				Signature: make([]byte, 64),
			}
		}
		tb.tx.WitnessSet.VKeyWitnessSet = append(tb.tx.WitnessSet.VKeyWitnessSet, additionalVKeyWitnessSet...)
	}

	// checking for auxiliary_data and if present add a fake 32 bytes for the future hash
	if tb.tx.AuxiliaryData != nil {
		fakeAuxDataHash32 := Hash32(make([]byte, 32))
		tb.tx.Body.AuxiliaryDataHash = &fakeAuxDataHash32
	}

	txLength := uint64(len(tb.tx.Bytes()))

	// restore tx as it was before to add fake additionalWitnesses
	if tb.additionalWitnesses > 0 {
		tb.tx.WitnessSet.VKeyWitnessSet = tb.tx.WitnessSet.VKeyWitnessSet[:len(tb.tx.WitnessSet.VKeyWitnessSet)-int(tb.additionalWitnesses)]
	}

	if tb.tx.AuxiliaryData != nil {
		tb.tx.Body.AuxiliaryDataHash = nil
	}
	//////// the below is just an old a bit arbitrary approach, here just for memories/references,
	//////// replaced by fake/empty additionalWitnesses approach
	// // for each additional witnesses there will be an additional 100 bytes,
	// // (32 public key, 64 signature, 4 index/key in cbor)
	// txLength += uint64(tb.additionalWitnesses * 100)
	// // apparently that is not enough, so just consider 1 additional byte
	// // for each additional witness after the first
	// if tb.additionalWitnesses > 1 {
	// 	txLength += uint64(tb.additionalWitnesses - 1)
	// }

	return tb.protocol.MinFeeA*Coin(txLength) + tb.protocol.MinFeeB + tb.additionalFee
}

// Sign adds signing keys to create signatures for the witness set.
func (tb *TxBuilder) Sign(privateKeys ...crypto.PrvKey) {
	tb.pkeys = append(tb.pkeys, privateKeys...)
}

// Reset resets the builder to its initial state.
func (tb *TxBuilder) Reset() {
	tb.tx = &Tx{IsValid: true}
	tb.pkeys = []crypto.PrvKey{}
	tb.changeReceiver = nil
}

// BuildWithoutValidation returns a new transaction without any
// attempt to validate the transaction is balanced.
func (tb *TxBuilder) BuildWithoutValidation() (*Tx, error) {
	if err := tb.build(); err != nil {
		return nil, err
	}

	return tb.tx, nil
}

func (tb *TxBuilder) SetWrappedTxBody(wrappedTxBody []byte) {
	tb.tx.Body.WrappedTxBody = wrappedTxBody
}

// Build returns a new transaction using the inputs, outputs and keys provided.
func (tb *TxBuilder) Build() (*Tx, error) {
	inputAmount, outputAmount := tb.calculateAmounts()

	// If we don't have an input amount (this is the case when
	// we're using an imported transaction from cardano-wallet
	// with NewTxBuilderFromTransaction()) we have to assume the
	// transaction was already built properly.
	if !inputAmount.IsZero() {
		// Check input-output value conservation
		if tb.changeReceiver == nil {
			totalProduced := outputAmount.Add(NewValue(tb.tx.Body.Fee))
			if inputOutputCmp := totalProduced.Cmp(inputAmount); inputOutputCmp == 1 || inputOutputCmp == 2 {
				return nil, fmt.Errorf(
					"insufficient input in transaction, got %v want %v",
					inputAmount,
					totalProduced,
				)
			} else if inputOutputCmp == -1 {
				return nil, fmt.Errorf(
					"fee too small, got %v want %v",
					tb.tx.Body.Fee,
					inputAmount.Sub(totalProduced),
				)
			}
		}

		if tb.changeReceiver != nil {
			err := tb.addChangeIfNeeded(inputAmount, outputAmount)
			if err != nil {
				return nil, err
			}
		}
	}

	return tb.BuildWithoutValidation()
}

func (tb *TxBuilder) addChangeIfNeeded(inputAmount, outputAmount *Value) error {
	// Temporary fee to serialize a valid transaction
	tb.tx.Body.Fee = 2e5

	// TODO: We should build a fake tx with hardcoded data like signatures, hashes, etc
	if err := tb.build(); err != nil {
		return err
	}

	minFee := tb.calculateMinFee()
	outputAmount = outputAmount.Add(NewValue(minFee))

	if inputOutputCmp := inputAmount.Cmp(outputAmount); inputOutputCmp == -1 || inputOutputCmp == 2 {
		return fmt.Errorf(
			"insufficient input in transaction, got %v want atleast %v",
			inputAmount,
			outputAmount,
		)
	} else if inputOutputCmp == 0 {
		tb.tx.Body.Fee = minFee
		return nil
	}

	// Construct change output
	changeAmount := inputAmount.Sub(outputAmount)
	changeOutput := NewTxOutput(*tb.changeReceiver, changeAmount)

	changeMinCoins := tb.MinCoinsForTxOut(changeOutput)
	if changeAmount.Coin < changeMinCoins {
		if changeAmount.OnlyCoin() {
			tb.tx.Body.Fee = minFee + changeAmount.Coin // burn change
			return nil
		}
		return fmt.Errorf(
			"insufficient input for change output with multiassets, got %v want %v",
			inputAmount.Coin,
			inputAmount.Coin+changeMinCoins-changeAmount.Coin,
		)
	}

	tb.tx.Body.Outputs = append([]*TxOutput{changeOutput}, tb.tx.Body.Outputs...)

	newMinFee := tb.calculateMinFee()
	changeAmount.Coin = changeAmount.Coin + minFee - newMinFee
	if changeAmount.Coin < changeMinCoins {
		if changeAmount.OnlyCoin() {
			tb.tx.Body.Fee = newMinFee + changeAmount.Coin // burn change
			tb.tx.Body.Outputs = tb.tx.Body.Outputs[1:]    // remove change output
			return nil
		}
		return fmt.Errorf(
			"insufficient input for change output with multiassets, got %v want %v",
			inputAmount.Coin,
			changeMinCoins,
		)
	}

	tb.tx.Body.Fee = newMinFee

	return nil
}

func (tb *TxBuilder) build() error {
	if err := tb.buildBody(); err != nil {
		return err
	}

	txHash, err := tb.tx.Hash()
	if err != nil {
		return err
	}

	//fmt.Println("unsign tx: ", hex.EncodeToString(tb.tx.Bytes()))
	// Create witness set
	tb.tx.WitnessSet.VKeyWitnessSet = make([]VKeyWitness, len(tb.pkeys))
	for i, pkey := range tb.pkeys {
		tb.tx.WitnessSet.VKeyWitnessSet[i] = VKeyWitness{
			VKey: pkey.PubKey(),
			// for transaction we use Extended version of Sign method, not the ed25519 signing way
			Signature: pkey.SignExtended(txHash),
		}
	}

	return nil
}

func (tb *TxBuilder) buildBody() error {
	if tb.tx.AuxiliaryData != nil {
		auxBytes, err := cborEnc.Marshal(tb.tx.AuxiliaryData)
		if err != nil {
			return err
		}
		auxHash := blake2b.Sum256(auxBytes)
		auxHash32 := Hash32(auxHash[:])
		tb.tx.Body.AuxiliaryDataHash = &auxHash32
	}
	return nil
}
