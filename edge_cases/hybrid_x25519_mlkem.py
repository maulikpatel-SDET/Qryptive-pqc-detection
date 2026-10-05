"""TC-24  Hybrid key exchange: X25519 (classical ECC) + ML-KEM-768 (PQC).

Expected: Qryptive reports this as HYBRID (or reports ML-KEM-768 as PQC-safe and
X25519 separately as classical ECC). It must not mark the whole file as
"RSA" or ignore the ML-KEM part.
"""
import hashlib
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# classical half
alice_x = X25519PrivateKey.generate()
bob_x = X25519PrivateKey.generate()
x_secret = alice_x.exchange(bob_x.public_key())

# post-quantum half
with oqs.KeyEncapsulation("ML-KEM-768") as alice, oqs.KeyEncapsulation("ML-KEM-768") as bob:
    pk = alice.generate_keypair()
    ct, pq_secret = bob.encap_secret(pk)
    assert alice.decap_secret(ct) == pq_secret

hybrid_secret = hashlib.sha3_256(x_secret + pq_secret).digest()
print("hybrid secret:", hybrid_secret.hex())
