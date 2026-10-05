// TC-17  Go circl  OLD names: Kyber768 + Dilithium mode3.
// Purpose: pre-standard names must also be recognised as PQC.
package main

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
	kem := kyber768.Scheme()
	pk, sk, _ := kem.GenerateKeyPair()
	ct, ss1, _ := kem.Encapsulate(pk)
	ss2, _ := kem.Decapsulate(sk, ct)
	fmt.Println("Kyber768 secrets match:", bytes.Equal(ss1, ss2))

	sigScheme := mode3.Scheme()
	spk, ssk, _ := sigScheme.GenerateKey()
	msg := []byte("legacy names")
	sig := sigScheme.Sign(ssk, msg, nil)
	fmt.Println("Dilithium mode3 valid:", sigScheme.Verify(spk, msg, sig, nil))
}
