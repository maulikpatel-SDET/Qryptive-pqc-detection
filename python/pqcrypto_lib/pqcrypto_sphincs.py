"""TC-08  pqcrypto  SPHINCS+ SHA2-128f-simple signature."""
from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair, sign, verify

message = b"qryptive pqc detection test"
public_key, secret_key = generate_keypair()
signature = sign(secret_key, message)
assert verify(public_key, message, signature)
print("pqcrypto SPHINCS+ OK")
