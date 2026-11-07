from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

key = _rsa.generate_private_key(65537, 4096)
