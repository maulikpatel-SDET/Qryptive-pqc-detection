/* TC-10  liboqs (C)  ML-KEM-768 key encapsulation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) { fprintf(stderr, "ML-KEM-768 not enabled\n"); return 1; }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
    OQS_KEM_decaps(kem, ss_dec, ct, sk);

    printf("ML-KEM-768 shared secrets match: %s\n",
           memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0 ? "yes" : "no");

    OQS_MEM_secure_free(sk, kem->length_secret_key);
    free(pk); free(ct); free(ss_enc); free(ss_dec);
    OQS_KEM_free(kem);
    return 0;
}
