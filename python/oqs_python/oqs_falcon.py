"""TC-03  oqs-python  Falcon-512 (FN-DSA) signature."""
import oqs

SIG_ALG = "Falcon-512"
MESSAGE = b"qryptive pqc detection test"


def falcon_sign_verify():
    with oqs.Signature(SIG_ALG) as signer, oqs.Signature(SIG_ALG) as verifier:
        public_key = signer.generate_keypair()
        signature = signer.sign(MESSAGE)
        return verifier.verify(MESSAGE, signature, public_key)


if __name__ == "__main__":
    print("Falcon-512 signature valid:", falcon_sign_verify())
