from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())
peer_key = ec.generate_private_key(ec.SECP256R1()).public_key()
shared = private_key.exchange(ec.ECDH(), peer_key)
