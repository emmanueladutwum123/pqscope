import hashlib
import hmac


def tag(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()
