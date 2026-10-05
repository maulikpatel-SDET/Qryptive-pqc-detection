"""TC-05  pqcrypto  ML-KEM-768 key encapsulation."""
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt

public_key, secret_key = generate_keypair()
ciphertext, sender_secret = encrypt(public_key)
receiver_secret = decrypt(secret_key, ciphertext)
assert sender_secret == receiver_secret
print("pqcrypto ML-KEM-768 OK")
