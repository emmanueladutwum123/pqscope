from nacl.public import PrivateKey
from nacl.signing import SigningKey

sk = SigningKey.generate()
bk = PrivateKey.generate()
