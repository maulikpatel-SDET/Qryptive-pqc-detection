// TC-16  Go circl  SLH-DSA (SPHINCS+) SHA2-128f signature.
// circl has no Falcon implementation, so Falcon is not tested for Go.
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/slhdsa"
)

func main() {
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		panic(err)
	}
	msg := slhdsa.NewMessage([]byte("qryptive pqc detection test"))
	sig, err := slhdsa.SignDeterministic(&priv, msg, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("SLH-DSA signature valid:", slhdsa.Verify(&pub, msg, sig, nil))
}
