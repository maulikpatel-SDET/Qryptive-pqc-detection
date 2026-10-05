"""TC-02  oqs-python  ML-DSA-65 (formerly Dilithium3) signature."""
import oqs

SIG_ALG = "ML-DSA-65"
MESSAGE = b"qryptive pqc detection test"


def mldsa_sign_verify():
    with oqs.Signature(SIG_ALG) as signer, oqs.Signature(SIG_ALG) as verifier:
        public_key = signer.generate_keypair()
        signature = signer.sign(MESSAGE)
        return verifier.verify(MESSAGE, signature, public_key)


if __name__ == "__main__":
    print("ML-DSA-65 signature valid:", mldsa_sign_verify())
