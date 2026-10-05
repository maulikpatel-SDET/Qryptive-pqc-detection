"""TC-26  CONTROL - classical RSA-2048. Qryptive SHOULD flag this as quantum-vulnerable."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
signature = private_key.sign(b"control", padding.PKCS1v15(), hashes.SHA256())
print("RSA signature length:", len(signature))
