package cose

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/safanaj/cardano-go/internal/cbor"
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

func NewSignerFromCOSEKey(key *COSEKey) (cose.Signer, error) {
	if len(key.Key.Bytes()) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is wrong size (expected: %d): %d", ed25519.PrivateKeySize, len(key.Key.Bytes()))
	}
	if cose.Algorithm(key.Alg) != cose.AlgorithmEd25519 {
		return nil, fmt.Errorf("alg is wrong, not Ed25519 (value %v): %v", cose.AlgorithmEd25519, cose.Algorithm(key.Alg))
	}
	return cose.NewSigner(cose.AlgorithmEd25519, ed25519.PrivateKey(key.Key.Bytes()))
}
func NewSignerFromCBORHex(cborHex string) (cose.Signer, error) {
	key, err := NewCOSEKeyFromCBORHex(cborHex)
	if err != nil {
		return nil, err
	}
	return NewSignerFromCOSEKey(key)
}

func SignPayloadWithKeyFromCBORHex(payload, key string) (string, error) {
	signer, err := NewSignerFromCBORHex(key)
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

func SignWithKey(payload, key []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("key is wrong size (expected: %d): %d", ed25519.PrivateKeySize, len(key))
	}
	coseKey := &COSEKey{
		Crv: uint64(6),
		Kty: uint64(1),
		Alg: int64(cose.AlgorithmEd25519),
	}
	copy(coseKey.Key.Bytes(), key)
	// keyId := ed25519.PrivateKey(key).prvKey.Public().(ed25519.PublicKey) // should be used as key id
	// copy(coseKey.Kid, keyId)

	signer, err := NewSignerFromCOSEKey(coseKey)
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
	return msgToVerify.Sign1Message.Verify(nil, verifier)
}

////////////////////////////////////////////////////////////////

// const (
// 	kCrvKey int64  = -1
// 	kKeyKey int64  = -2
// 	kKtyKey uint64 = 1
// 	kKidKey uint64 = 2
// 	kAlgKey uint64 = 3
// )

// func (k *COSEKey) UnmarshalCBOR_viaMap(data []byte) error {
// 	var rck map[any]any
// 	err := cbor.Unmarshal(data, &rck)
// 	if err != nil {
// 		return err
// 	}
// 	if vI, ok := rck[kCrvKey]; !ok {
// 		return fmt.Errorf("crv key missing")
// 	} else {
// 		if v, ok := vI.(uint64); !ok {
// 			return fmt.Errorf("crv key value is not a uint64: %T", vI)
// 		} else if v != uint64(6) {
// 			return fmt.Errorf("crv key is not Ed25519 (value 6): %v", v)
// 		} else {
// 			k.Crv = v
// 		}
// 	}

// 	if vI, ok := rck[kKeyKey]; !ok {
// 		return fmt.Errorf("key key missing")
// 	} else {
// 		if v, ok := vI.([]byte); !ok {
// 			return fmt.Errorf("key key value is not a []byte: %T", vI)
// 		} else {
// 			if len(v) != ed25519.PublicKeySize && len(v) != ed25519.PrivateKeySize {
// 				return fmt.Errorf("key is wrong size (expected %d or %d): %d", ed25519.PublicKeySize, ed25519.PrivateKeySize, len(v))
// 			} else {
// 				k.Key = make([]byte, len(v))
// 				copy(k.Key, v)
// 			}
// 		}
// 	}

// 	if vI, ok := rck[kKtyKey]; !ok {
// 		return fmt.Errorf("kty key missing")
// 	} else {
// 		if v, ok := vI.(uint64); !ok {
// 			return fmt.Errorf("kty key value is not a uint64: %T", vI)
// 		} else if v != uint64(1) {
// 			return fmt.Errorf("kty key is not OKP (value 1): %v", v)
// 		} else {
// 			k.Kty = v
// 		}
// 	}

// 	if vI, ok := rck[kAlgKey]; !ok {
// 		return fmt.Errorf("alg key missing")
// 	} else {
// 		if v, ok := vI.(int64); !ok {
// 			return fmt.Errorf("alg key value is not a int64: %T", vI)
// 		} else if cose.Algorithm(v) != cose.AlgorithmEd25519 {
// 			return fmt.Errorf("alg is wrong, not Ed25519 (value %v): %v", cose.AlgorithmEd25519, cose.Algorithm(v))
// 		} else {
// 			k.Alg = v
// 		}
// 	}

// 	if vI, ok := rck[kKidKey]; ok {
// 		if v, ok := vI.([]byte); !ok {
// 			return fmt.Errorf("kid key value is not a []byte: %T", vI)
// 		} else {
// 			k.Kid = make([]byte, len(v))
// 			copy(k.Kid, v)
// 		}
// 	}
// 	return nil
// }

// func (k *COSEKey) MarshalCBOR_viaMap() ([]byte, error) {
// 	rck := make(map[any]any)
// 	rck[kCrvKey] = uint64(6)
// 	rck[kKtyKey] = uint64(1)
// 	rck[kAlgKey] = int64(cose.AlgorithmEd25519)
// 	keyBuf := make([]byte, len(k.Key))
// 	copy(keyBuf, k.Key)
// 	rck[kKeyKey] = keyBuf
// 	if k.Kid != nil {
// 		kidBuf := make([]byte, len(k.Kid))
// 		copy(kidBuf, k.Kid)
// 		rck[kKidKey] = kidBuf
// 	}
// }
