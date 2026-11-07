from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def store(key: RSAPrivateKey) -> None:
    keyring = [key]
    print(len(keyring))
