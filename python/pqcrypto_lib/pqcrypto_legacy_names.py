"""TC-09  pqcrypto  OLD algorithm names: Kyber512 + Dilithium2 (pqcrypto <= 0.1.x).

Purpose: Qryptive must recognise the pre-standard names (Kyber / Dilithium)
as PQC, not only the new NIST names (ML-KEM / ML-DSA).
"""
from pqcrypto.kem.kyber512 import generate_keypair as kyber_keypair, encrypt, decrypt
from pqcrypto.sign.dilithium2 import generate_keypair as dilithium_keypair, sign, verify

pk, sk = kyber_keypair()
ct, ss_sender = encrypt(pk)
assert decrypt(sk, ct) == ss_sender

spk, ssk = dilithium_keypair()
msg = b"legacy names"
assert verify(spk, msg, sign(ssk, msg))
print("Kyber512 + Dilithium2 OK")
