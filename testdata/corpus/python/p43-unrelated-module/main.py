import myapp.crypto.rsa as rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
