from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
ct = key.public_key().encrypt(b"x", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
