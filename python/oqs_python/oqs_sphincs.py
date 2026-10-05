"""TC-04  oqs-python  SPHINCS+ (SLH-DSA) signature.

Newer liboqs builds expose SLH-DSA names; older builds expose "SPHINCS+-..." names.
The code picks whichever one the installed build supports.
"""
import oqs

CANDIDATES = ["SLH_DSA_PURE_SHA2_128F", "SPHINCS+-SHA2-128f-simple"]
MESSAGE = b"qryptive pqc detection test"


def pick_alg():
    enabled = oqs.get_enabled_sig_mechanisms()
    for name in CANDIDATES:
        if name in enabled:
            return name
    raise RuntimeError("No SPHINCS+/SLH-DSA mechanism enabled in this liboqs build")


def sphincs_sign_verify():
    alg = pick_alg()
    with oqs.Signature(alg) as signer, oqs.Signature(alg) as verifier:
        public_key = signer.generate_keypair()
        signature = signer.sign(MESSAGE)
        return alg, verifier.verify(MESSAGE, signature, public_key)


if __name__ == "__main__":
    print("SPHINCS+ / SLH-DSA (alg, valid):", sphincs_sign_verify())
