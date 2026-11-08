from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP384R1())
sig = key.sign(b"data", ec.ECDSA(hashes.SHA384()))
