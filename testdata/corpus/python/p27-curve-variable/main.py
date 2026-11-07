from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256R1()
key = ec.generate_private_key(CURVE)
