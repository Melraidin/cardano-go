package libsodium

//go:generate go run ./build_libsodium_helper.go _c_libsodium_built

/*
#cgo CFLAGS: -Wall
#cgo LDFLAGS: -l:libsodium.a
#include <sodium/core.h>
#include <sodium/crypto_vrf.h>
#include <sodium/crypto_vrf_ietfdraft03.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	_ "github.com/otiai10/copy"
	"github.com/safanaj/cardano-go"
	"golang.org/x/crypto/blake2b"
)

func getBytesFromCBORHexOrDie(cborHex string) []byte {
	data, err := cardano.GetBytesFromCBORHex(cborHex)
	if err != nil {
		panic(err)
	}
	return data
}

func MkSeed(slot int, eta0 string) []byte {
	eta0bytes, _ := hex.DecodeString(eta0)
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, int64(slot))
	h := blake2b.Sum256(append(buff.Bytes(), eta0bytes...))
	return h[:]
}

var (
	sodium_init_rc   int
	sodium_init_once sync.Once
)

func Initialize_libsodium() int {
	sodium_init_once.Do(func() {
		sodium_init_rc = int(C.sodium_init())
	})
	return sodium_init_rc
}

func CryptoVrfProofToHash(proof []byte) ([]byte, error) {
	if len(proof) != int(C.int(C.crypto_vrf_proofbytes())) {
		return nil, fmt.Errorf("Invalid proof")
	}
	hash := make([]byte, C.int(C.crypto_vrf_outputbytes()))
	rc := C.int(C.crypto_vrf_proof_to_hash((*C.uchar)((&hash[0])), (*C.uchar)((&proof[0]))))
	if rc != 0 {
		return nil, fmt.Errorf("Failed crypto_vrf_proof_to_hash. return code: %d", rc)
	}
	return hash, nil
}

func CryptoVrfProve(sk, seed []byte) ([]byte, error) {
	fmt.Printf("CryptoVrfProve\n")
	if len(sk) != int(C.int(C.crypto_vrf_secretkeybytes())) {
		fmt.Printf("CryptoVrfProve: Invalid vrf private key\n")
		return nil, fmt.Errorf("Invalid vrf private key")
	}
	if len(seed) != int(C.int(C.crypto_vrf_seedbytes())) {
		fmt.Printf("CryptoVrfProve: Invalid data to sign/prove\n")
		return nil, fmt.Errorf("Invalid data to sign/prove")
	}

	proof := make([]byte, C.int(C.crypto_vrf_proofbytes()))
	rc := C.int(C.crypto_vrf_prove((*C.uchar)(&proof[0]), (*C.uchar)(&sk[0]), (*C.uchar)(&seed[0]), C.ulonglong(len(seed))))
	fmt.Printf("cap: %d - len: %d -- %v ---> rc: %d\n", cap(proof), len(proof), proof, rc)
	if rc != 0 {
		return nil, fmt.Errorf("Failed crypto_vrf_proof_to_hash. return code: %d", rc)
	}
	fmt.Printf("cap: %d - len: %d -- %v\n", cap(proof), len(proof), proof)
	return proof, nil
}

func CryptoVrfVerify(pk, proof, seed []byte) ([]byte, error) {
	if C.int(len(pk)) != C.int(C.crypto_vrf_publickeybytes()) {
		return nil, fmt.Errorf("Invalid vrf public key")
	}
	if C.int(len(seed)) != C.int(C.crypto_vrf_seedbytes()) {
		return nil, fmt.Errorf("Invalid data to sign/prove")
	}
	if C.int(len(proof)) != C.int(C.crypto_vrf_proofbytes()) {
		return nil, fmt.Errorf("Invalid proof")
	}

	out := make([]byte, C.int(C.crypto_vrf_outputbytes()))
	rc := C.int(C.crypto_vrf_verify((*C.uchar)(&out[0]), (*C.uchar)(&pk[0]), (*C.uchar)(&proof[0]), (*C.uchar)(&seed[0]), C.ulonglong(len(seed))))
	if rc != 0 {
		return nil, fmt.Errorf("Failed crypto_vrf_verify. return code: %d", rc)
	}
	return out, nil
}

func GetVrfCert(seed, vrfSkey []byte) *big.Int {
	proofBytes := make([]byte, C.int(C.crypto_vrf_ietfdraft03_proofbytes()))
	C.crypto_vrf_prove(
		(*C.uchar)((&proofBytes[0])),
		(*C.uchar)(&vrfSkey[0]),
		(*C.uchar)((&seed[0])),
		(C.ulonglong)(len(seed)))
	outBytes := make([]byte, C.int(C.crypto_vrf_outputbytes()))
	C.crypto_vrf_proof_to_hash((*C.uchar)((&outBytes[0])), (*C.uchar)((&proofBytes[0])))
	return big.NewInt(0).SetBytes(outBytes)
}

// should double check with: https://github.com/cardano-community/cncli/blob/develop/src/nodeclient/leaderlog.rs#L327
func getVrfLeaderValue(raw *big.Int) *big.Int {
	var val [64]byte
	raw.FillBytes(val[:])
	h := blake2b.Sum256(append([]byte{0x4C}, val[:]...))
	return big.NewInt(0).SetBytes(h[:])
}

func GetVrfMaxValue() *big.Int { return big.NewInt(0).Exp(big.NewInt(2), big.NewInt(256), nil) }

func GetVrfLeaderValue(slot int, eta0, cborHex string) *big.Int {
	seed := MkSeed(slot, eta0)
	cert := GetVrfCert(seed, getBytesFromCBORHexOrDie(cborHex))
	return getVrfLeaderValue(cert)
}
