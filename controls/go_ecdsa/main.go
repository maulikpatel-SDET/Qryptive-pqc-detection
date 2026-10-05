// TC-27  CONTROL - classical ECDSA P-256. Qryptive SHOULD flag this as quantum-vulnerable.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func main() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := sha256.Sum256([]byte("control"))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
	fmt.Println("ECDSA valid:", ecdsa.VerifyASN1(&key.PublicKey, h[:], sig))
}
