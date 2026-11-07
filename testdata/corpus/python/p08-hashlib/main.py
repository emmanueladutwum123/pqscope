import hashlib


def digests(data):
    yield hashlib.md5(data).hexdigest()
    yield hashlib.sha1(data).hexdigest()
    yield hashlib.sha256(data).hexdigest()
    yield hashlib.new("sha512", data).hexdigest()
