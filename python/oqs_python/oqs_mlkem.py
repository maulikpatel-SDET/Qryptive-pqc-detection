"""TC-01  oqs-python  ML-KEM-768 (formerly Kyber768) key encapsulation."""
import oqs

KEM_ALG = "ML-KEM-768"


def mlkem_handshake():
    with oqs.KeyEncapsulation(KEM_ALG) as client, oqs.KeyEncapsulation(KEM_ALG) as server:
        public_key = client.generate_keypair()
        ciphertext, server_secret = server.encap_secret(public_key)
        client_secret = client.decap_secret(ciphertext)
        assert client_secret == server_secret
        return client_secret


if __name__ == "__main__":
    print("ML-KEM-768 shared secret:", mlkem_handshake().hex())
