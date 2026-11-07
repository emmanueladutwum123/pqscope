from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign(key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
