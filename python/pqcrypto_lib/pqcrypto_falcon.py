"""TC-07  pqcrypto  Falcon-512 signature."""
from pqcrypto.sign.falcon_512 import generate_keypair, sign, verify

message = b"qryptive pqc detection test"
public_key, secret_key = generate_keypair()
signature = sign(secret_key, message)
assert verify(public_key, message, signature)
print("pqcrypto Falcon-512 OK")
