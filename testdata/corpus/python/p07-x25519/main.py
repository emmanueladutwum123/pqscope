from cryptography.hazmat.primitives.asymmetric import x25519

a = x25519.X25519PrivateKey.generate()
b = x25519.X25519PrivateKey.generate()
secret = a.exchange(b.public_key())
