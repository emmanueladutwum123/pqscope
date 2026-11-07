from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
