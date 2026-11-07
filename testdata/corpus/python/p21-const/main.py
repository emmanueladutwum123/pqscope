from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 3072


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
