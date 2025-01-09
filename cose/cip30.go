package cose

import (
	cryptolib "crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/melraidin/cardano-go/crypto"
	"github.com/melraidin/cardano-go/internal/cbor"
	"github.com/veraison/go-cose"
)

type COSEKey struct {
	Crv uint64          `cbor:"-1,keyasint"`
	Key cbor.ByteString `cbor:"-2,keyasint"`
	Kty uint64          `cbor:"1,keyasint"`
	Kid cbor.ByteString `cbor:"2,keyasint,omitempty"`
	Alg int64           `cbor:"3,keyasint"`
}

func (k *COSEKey) UnmarshalCBOR(data []byte) error {
	type rawCOSEKey COSEKey
	var rck rawCOSEKey

	err := cbor.Unmarshal(data, &rck)
	if err != nil {
		return err
	}
	if rck.Crv != uint64(6) {
		return fmt.Errorf("crv key is not Ed25519 (value 6): %v", rck.Crv)
	}

	if len(rck.Key.Bytes()) != ed25519.PublicKeySize && len(rck.Key.Bytes()) != ed25519.PrivateKeySize {
		return fmt.Errorf("key is wrong size (expected %d or %d): %d", ed25519.PublicKeySize, ed25519.PrivateKeySize, len(rck.Key.Bytes()))
	}

	if rck.Kty != uint64(1) {
		return fmt.Errorf("kty is wrong, not OKP (value 1): %v", rck.Kty)
	}

	if cose.Algorithm(rck.Alg) != cose.AlgorithmEd25519 {
		return fmt.Errorf("alg is wrong, not Ed25519 (value %v): %v", cose.AlgorithmEd25519, cose.Algorithm(rck.Alg))
	}

	k.Crv = rck.Crv
	k.Key = rck.Key
	k.Kty = rck.Kty
	k.Kid = rck.Kid
	k.Alg = rck.Alg

	return nil
}

func (k *COSEKey) MarshalCBOR() ([]byte, error) {
	type rawCOSEKey COSEKey
	rck := &rawCOSEKey{
		Crv: uint64(6),
		Kty: uint64(1),
		Alg: int64(cose.AlgorithmEd25519),
		Key: k.Key,
		Kid: k.Kid,
	}
	return cbor.Marshal(rck)
}

func NewCOSEKeyFromBytes(key []byte) (*COSEKey, error) {
	if len(key) != ed25519.PublicKeySize && len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is wrong size (expected %d or %d): %d", ed25519.PublicKeySize, ed25519.PrivateKeySize, len(key))
	}

	coseKey := &COSEKey{
		Crv: uint64(6),
		Kty: uint64(1),
		Alg: int64(cose.AlgorithmEd25519),
		Key: cbor.NewByteString(key),
	}

	var (
		keyId []byte
		err   error
	)

	// if len(key) == ed25519.PublicKeySize {
	// 	keyId, err = crypto.PubKey(key).Hash()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// } else {
	// 	keyId, err = crypto.PrvKey(key).PubKey().Hash()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	// if keyId != nil {
	// 	// copy(coseKey.Kid.Bytes(), keyId)
	// 	coseKey.Kid = cbor.NewByteString(keyId)
	// }
	_ = keyId
	_ = err

	return coseKey, nil
}

func NewCOSEKeyFromCBORHex(cborHex string) (*COSEKey, error) {
	data, err := hex.DecodeString(cborHex)
	if err != nil {
		return nil, err
	}
	key := &COSEKey{}
	if err := cbor.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	return key, nil
}

type COSESign1Message struct {
	*cose.Sign1Message
}

func (m *COSESign1Message) UnmarshalCBOR(data []byte) error {
	data_ := data[:]
	if data_[0] != 0xd2 {
		data_ = append([]byte{0xd2}, data_...)
	}
	if m.Sign1Message == nil {
		m.Sign1Message = &cose.Sign1Message{}
	}
	return m.Sign1Message.UnmarshalCBOR(data_)
}
func (m *COSESign1Message) MarshalCBOR() ([]byte, error) {
	data, err := m.Sign1Message.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	if data[0] == 0xd2 {
		return data[1:], nil
	}
	return data, nil
}

func NewCOSESign1MessageFromCBORHex(cborHex string) (*COSESign1Message, error) {
	data, err := hex.DecodeString(cborHex)
	if err != nil {
		return nil, err
	}
	msg := &COSESign1Message{&cose.Sign1Message{}}
	if err := cbor.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func NewCOSESign1MessageWithPayload(payload string, kid []byte) *COSESign1Message {
	sign1msg := cose.NewSign1Message()
	sign1msg.Payload = []byte(payload)
	sign1msg.Headers.Unprotected["hashed"] = false
	sign1msg.Headers.Protected.SetAlgorithm(cose.AlgorithmEd25519)
	if kid != nil {
		sign1msg.Headers.Protected[cose.HeaderLabelKeyID] = kid
		sign1msg.Headers.Protected["address"] = kid
	}
	return &COSESign1Message{sign1msg}
}

// //////////////////////////////////////////////////////////////
// standard and extended hook to create a signer from COSEKey
func ed25519_NewSignerFunc(key *COSEKey) cryptolib.Signer {
	return crypto.PrvKey(key.Key.Bytes()).PrivateKey()
}
func ed25519e_NewSignerFunc(key *COSEKey) cryptolib.Signer {
	return crypto.PrvKey(key.Key.Bytes()).ExtendedEd25519Signer()
}

// //////////////////////////////////////////////////////////////
// generic signer factory

func newSignerFromKey(key *COSEKey, doNewSigner func(key *COSEKey) cryptolib.Signer) (cose.Signer, error) {
	if len(key.Key.Bytes()) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is wrong size (expected: %d): %d", ed25519.PrivateKeySize, len(key.Key.Bytes()))
	}
	if cose.Algorithm(key.Alg) != cose.AlgorithmEd25519 {
		return nil, fmt.Errorf("alg is wrong, not Ed25519 (value %v): %v", cose.AlgorithmEd25519, cose.Algorithm(key.Alg))
	}
	return cose.NewSigner(cose.AlgorithmEd25519, doNewSigner(key))
}

func newSignerFromCBORHex(cborHex string, doNewSigner func(key *COSEKey) cryptolib.Signer) (cose.Signer, error) {
	key, err := NewCOSEKeyFromCBORHex(cborHex)
	if err != nil {
		return nil, err
	}
	return newSignerFromKey(key, doNewSigner)
}

func signPayloadWithKeyFromCBORHex(payload, key string, doNewSigner func(key *COSEKey) cryptolib.Signer) (string, error) {
	signer, err := newSignerFromCBORHex(key, doNewSigner)
	if err != nil {
		return "", err
	}
	msgToSign := NewCOSESign1MessageWithPayload(payload, nil)
	if err := msgToSign.Sign(nil, nil, signer); err != nil {
		return "", err
	}
	cborBytes, err := cbor.Marshal(msgToSign)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cborBytes), nil
}

func signWithKey(payload, key []byte, doNewSigner func(key *COSEKey) cryptolib.Signer) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("key is wrong size (expected: %d): %d", ed25519.PrivateKeySize, len(key))
	}
	coseKey := &COSEKey{
		Crv: uint64(6),
		Kty: uint64(1),
		Alg: int64(cose.AlgorithmEd25519),
	}
	copy(coseKey.Key.Bytes(), key)

	signer, err := newSignerFromKey(coseKey, doNewSigner)
	if err != nil {
		return "", err
	}

	msgToSign := NewCOSESign1MessageWithPayload(string(payload), nil)
	if err := msgToSign.Sign(nil, nil, signer); err != nil {
		return "", err
	}
	cborBytes, err := cbor.Marshal(msgToSign)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cborBytes), nil
}

////////////////////////////////////////////////////////////////
// ed25519 signer

func NewSignerFromCOSEKey(key *COSEKey) (cose.Signer, error) {
	return newSignerFromKey(key, ed25519_NewSignerFunc)
}
func NewSignerFromCBORHex(cborHex string) (cose.Signer, error) {
	return newSignerFromCBORHex(cborHex, ed25519_NewSignerFunc)
}

func SignPayloadWithKeyFromCBORHex(payload, key string) (string, error) {
	return signPayloadWithKeyFromCBORHex(payload, key, ed25519_NewSignerFunc)
}

func SignWithKey(payload, key []byte) (string, error) {
	return signWithKey(payload, key, ed25519_NewSignerFunc)
}

// //////////////////////////////////////////////////////////////
// extended signer (ed25519e)
func NewExtendedSignerFromCOSEKey(key *COSEKey) (cose.Signer, error) {
	return newSignerFromKey(key, ed25519e_NewSignerFunc)

}
func NewExtendedSignerFromCBORHex(cborHex string) (cose.Signer, error) {
	return newSignerFromCBORHex(cborHex, ed25519e_NewSignerFunc)
}

func SignExtendedPayloadWithKeyFromCBORHex(payload, key string) (string, error) {
	return signPayloadWithKeyFromCBORHex(payload, key, ed25519e_NewSignerFunc)
}

func SignExtendedWithKey(payload, key []byte) (string, error) {
	return signWithKey(payload, key, ed25519e_NewSignerFunc)
}

////////////////////////////////////////////////////////////////
// verifier

func NewVerifierFromCOSEKey(key *COSEKey) (cose.Verifier, error) {
	if len(key.Key.Bytes()) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key is wrong size (expected: %d): %d", ed25519.PublicKeySize, len(key.Key.Bytes()))
	}
	if cose.Algorithm(key.Alg) != cose.AlgorithmEd25519 {
		return nil, fmt.Errorf("alg is wrong, not Ed25519 (value %v): %v", cose.AlgorithmEd25519, cose.Algorithm(key.Alg))
	}
	return cose.NewVerifier(cose.AlgorithmEd25519, ed25519.PublicKey(key.Key.Bytes()))
}
func NewVerifierFromCBORHex(cborHex string) (cose.Verifier, error) {
	key, err := NewCOSEKeyFromCBORHex(cborHex)
	if err != nil {
		return nil, err
	}
	return NewVerifierFromCOSEKey(key)
}

func VerifyFromCBORHex(signature, key string) error {
	verifier, err := NewVerifierFromCBORHex(key)
	if err != nil {
		return err
	}
	msgToVerify, err := NewCOSESign1MessageFromCBORHex(signature)
	if err != nil {
		return err
	}
	return msgToVerify.Verify(nil, verifier)
}
