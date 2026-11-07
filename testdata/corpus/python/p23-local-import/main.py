def fingerprint(data):
    from hashlib import sha1 as _sha1

    return _sha1(data).hexdigest()
