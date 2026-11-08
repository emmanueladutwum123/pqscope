import hashlib
import hmac

tag = hmac.new(b"key", b"msg", hashlib.sha256).digest()
