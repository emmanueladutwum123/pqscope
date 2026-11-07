from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
cipher = DES3.new(b"0" * 24, DES3.MODE_CBC)
