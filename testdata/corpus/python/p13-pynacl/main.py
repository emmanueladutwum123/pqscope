import nacl.public
from nacl.signing import SigningKey

signing_key = SigningKey.generate()
box_key = nacl.public.PrivateKey.generate()
