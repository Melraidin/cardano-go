package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"io"
	"strconv"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"

	"github.com/melraidin/cardano-go/internal/bech32"
)

// XPrvKey is the extended private key (64 bytes) appended with the chain code (32 bytes).
type XPrvKey []byte

// NewXPrvKey creates a new extended private key from a bech32 encoded private key.
func NewXPrvKey(bech string) (XPrvKey, error) {
	_, xsk, err := bech32.DecodeToBase256(bech)
	return xsk, err
}

//implements https://github.com/Emurgo/cardano-serialization-lib/blob/0e89deadf9183a129b9a25c0568eed177d6c6d7c/rust/src/crypto.rs#L123
func FromBip39Entropy(entropy []byte, password []byte) XPrvKey {
	return NewXPrvKeyFromEntropy(entropy, string(password))
}

func NewXPrvKeyFromEntropy(entropy []byte, password string) XPrvKey {
	key := pbkdf2.Key([]byte(password), entropy, 4096, 96, sha512.New)

	key[0] &= 0xf8
	key[31] = (key[31] & 0x1f) | 0x40

	return key
}

// Bech32 returns the private key encoded as bech32.
func (xsk XPrvKey) Bech32(prefix string) string {
	bech, err := bech32.EncodeFromBase256(prefix, xsk)
	if err != nil {
		panic(err)
	}
	return bech
}

func (xsk XPrvKey) String() string {
	return hex.EncodeToString(xsk)
}

// PrvKey returns the ed25519 extended private key.
func (xsk XPrvKey) PrvKey() PrvKey {
	prvKey := make([]byte, 64)
	copy(prvKey, xsk[:64])
	return prvKey
}

// XPubKey returns the XPubKey derived from the extended private key.
func (xsk XPrvKey) XPubKey() XPubKey {
	xvk := make([]byte, 64)
	vk := xsk.PrvKey().PubKey()
	cc := xsk[64:]

	copy(xvk[:32], vk)
	copy(xvk[32:], cc)

	return xvk
}

// XPubKey returns the XPubKey derived from the extended private key.
func (xsk XPrvKey) PubKey() PubKey {
	return xsk.PrvKey().PubKey()
}

func (xsk XPrvKey) Sign(message []byte) []byte {
	return xsk.PrvKey().Sign(message)
}

func (xsk XPrvKey) Seed() []byte {
	return xsk.PrvKey().Seed()
}

// XPubKey is the public key (32 bytes) appended with the chain code (32 bytes).
type XPubKey []byte

// NewXPubKey creates a new extended public key from a bech32 encoded extended public key.
func NewXPubKey(bech string) (XPubKey, error) {
	_, xvk, err := bech32.DecodeToBase256(bech)
	return xvk, err
}

// XPubKey returns the PubKey from the extended public key.
func (xvk XPubKey) PubKey() PubKey {
	pk := make([]byte, 32)
	copy(pk, xvk[:32])
	return pk
}

// NewPubKey creates a new public key from a bech32 encoded public key.
func NewPubKey(bech string) (PubKey, error) {
	_, vk, err := bech32.DecodeToBase256(bech)
	return vk, err
}

// Verify reports whether sig is a valid signature of message by the extended public key.
func (xvk XPubKey) Verify(message, sig []byte) bool {
	return xvk.PubKey().Verify(message, sig)
}

func (xvk XPubKey) String() string {
	return hex.EncodeToString(xvk)
}

// PubKey is a edd25519 public key.
type PubKey []byte

// Verify reports whether sig is a valid signature of message by the public key.
func (vk PubKey) Verify(message, signature []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(vk), message, signature)
}

// Bech32 returns the public key encoded as bech32.
func (vk PubKey) Bech32(prefix string) string {
	bech, err := bech32.EncodeFromBase256(prefix, vk)
	if err != nil {
		panic(err)
	}
	return bech
}

func (vk PubKey) String() string {
	return hex.EncodeToString(vk)
}

// Hash returns the public key hash using blake2b224.
func (vk PubKey) Hash() ([]byte, error) {
	return blake224Hash(vk)
}

// PrvKey is a ed25519 extended private key.
type PrvKey []byte

func (sk PrvKey) Seed() []byte {
	return sk[:32]
}

// NewPrvKey creates a new private key from a bech32 encoded private key.
func NewPrvKey(bech string) (PrvKey, error) {
	_, sk, err := bech32.DecodeToBase256(bech)
	return sk, err
}

// PubKey returns the PubKey derived from the private key.
func (sk PrvKey) PubKey() PubKey {
	// this is used for derivation, we are not hashing the seed
	s, _ := edwards25519.NewScalar().SetBytesWithClamping(sk.Seed())
	return PubKey((&edwards25519.Point{}).ScalarBaseMult(s).Bytes())

}

func (sk PrvKey) PrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(sk.Seed())
}

func (sk PrvKey) PublicKey() ed25519.PublicKey {
	h := sha512.Sum512(sk.Seed())
	s, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	return (&edwards25519.Point{}).ScalarBaseMult(s).Bytes()
}

// Bech32 returns the private key encoded as bech32.
func (sk PrvKey) Bech32(prefix string) string {
	bech, err := bech32.EncodeFromBase256(prefix, sk)
	if err != nil {
		panic(err)
	}
	return bech
}

func (sk PrvKey) String() string {
	return hex.EncodeToString(sk)
}

func (sk PrvKey) Sign(message []byte) []byte {
	sig, _ := sk.PrivateKey().Sign(nil, message, crypto.Hash(0))
	return sig
}

func (sk PrvKey) SignExtended(message []byte) []byte {
	if l := len(sk); l != ed25519.PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	sig := make([]byte, ed25519.SignatureSize)

	h := sha512.New()
	var messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	copy(expandedSecretKey[:], sk[:32])
	x, err := edwards25519.NewScalar().SetBytesWithClamping(expandedSecretKey[:])
	if err != nil {
		panic(err)
	}

	h.Write(sk[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	m, err := edwards25519.NewScalar().SetUniformBytes(messageDigest[:])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	encodedR := (&edwards25519.Point{}).ScalarBaseMult(m).Bytes()

	h.Reset()
	h.Write(encodedR[:])
	h.Write(sk.PubKey())
	h.Write(message)
	h.Sum(hramDigest[:0])

	r, err := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	s := edwards25519.NewScalar().MultiplyAdd(r, x, m).Bytes()

	copy(sig[:], encodedR[:])
	copy(sig[32:], s[:])

	return sig
}

type ExtendedPrivateKey PrvKey
type ExtendedEd25519Signer PrvKey

func (sk PrvKey) ExtendedPrivateKey() ExtendedPrivateKey {
	return ExtendedPrivateKey(sk)
}

func (esk ExtendedPrivateKey) Sign(message []byte) []byte {
	return PrvKey(esk).SignExtended(message)
}

func (sk PrvKey) ExtendedEd25519Signer() crypto.Signer {
	return ExtendedEd25519Signer(sk)
}

func (e ExtendedEd25519Signer) Public() crypto.PublicKey {
	return ed25519.PublicKey(PrvKey(e).PubKey())
}

func (e ExtendedEd25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return PrvKey(e).SignExtended(digest), nil
}

func blake224Hash(b []byte) ([]byte, error) {
	hash, err := blake2b.New(224/8, nil)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(b)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), err
}

func Sha3AndBlake2b224(raw []byte) ([]byte, error) {
	res := sha3.Sum256(raw)
	return blake224Hash(res[:])
}
