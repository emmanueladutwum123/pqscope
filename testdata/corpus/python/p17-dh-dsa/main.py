from cryptography.hazmat.primitives.asymmetric import dh, dsa

params = dh.generate_parameters(generator=2, key_size=2048)
dsa_key = dsa.generate_private_key(key_size=3072)
