// TC-14  Go circl  ML-KEM-768 key encapsulation.
package main

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func main() {
	scheme := mlkem768.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	ct, ssSender, err := scheme.Encapsulate(pk)
	if err != nil {
		panic(err)
	}
	ssReceiver, err := scheme.Decapsulate(sk, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println("ML-KEM-768 secrets match:", bytes.Equal(ssSender, ssReceiver))
}
