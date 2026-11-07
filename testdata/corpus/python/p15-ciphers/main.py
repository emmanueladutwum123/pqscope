from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def make(key):
    yield algorithms.TripleDES(key[:24])
    yield algorithms.ARC4(key)
    yield algorithms.AES(key[:32])
    yield ChaCha20Poly1305(key[:32])
