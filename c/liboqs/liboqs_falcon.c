/* TC-12  liboqs (C)  Falcon-512 signature. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) { fprintf(stderr, "Falcon-512 not enabled\n"); return 1; }

    const uint8_t msg[] = "qryptive pqc detection test";
    size_t msg_len = sizeof(msg) - 1;
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = 0;

    OQS_SIG_keypair(sig, pk, sk);
    OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, sk);
    OQS_STATUS ok = OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pk);

    printf("Falcon-512 signature valid: %s\n", ok == OQS_SUCCESS ? "yes" : "no");

    OQS_MEM_secure_free(sk, sig->length_secret_key);
    free(pk); free(signature);
    OQS_SIG_free(sig);
    return 0;
}
