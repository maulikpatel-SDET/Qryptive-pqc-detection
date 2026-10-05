"""TC-23  Misleading names: variables / comments mention RSA, ECC, DSA
but the ONLY algorithm actually used is ML-DSA-65 (post-quantum).

Expected: Qryptive must NOT raise an RSA / ECC / DSA finding here.
"""
import oqs

# Migration note: this module replaces the old RSA-2048 and ECDSA P-256 signing.
rsa_replacement_alg = "ML-DSA-65"
ecc_key_slot = None
dsa_signature = None


def sign_document(doc: bytes):
    global ecc_key_slot, dsa_signature
    with oqs.Signature(rsa_replacement_alg) as signer:
        ecc_key_slot = signer.generate_keypair()
        dsa_signature = signer.sign(doc)
    return dsa_signature
