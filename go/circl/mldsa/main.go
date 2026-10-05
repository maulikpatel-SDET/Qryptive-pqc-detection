// TC-15  Go circl  ML-DSA-65 signature.
package main

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	scheme := mldsa65.Scheme()
	pk, sk, err := scheme.GenerateKey()
	if err != nil {
		panic(err)
	}
	msg := []byte("qryptive pqc detection test")
	sig := scheme.Sign(sk, msg, nil)
	fmt.Println("ML-DSA-65 signature valid:", scheme.Verify(pk, msg, sig, nil))
}
