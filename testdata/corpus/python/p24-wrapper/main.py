from cryptography.hazmat.primitives.asymmetric import rsa


def gen(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


key = gen(2048)
