from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
