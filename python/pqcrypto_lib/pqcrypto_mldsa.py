"""TC-06  pqcrypto  ML-DSA-65 signature."""
from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify

message = b"qryptive pqc detection test"
public_key, secret_key = generate_keypair()
signature = sign(secret_key, message)
assert verify(public_key, message, signature)
print("pqcrypto ML-DSA-65 OK")
