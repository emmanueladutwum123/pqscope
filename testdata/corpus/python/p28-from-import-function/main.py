from hashlib import md5


def checksum(data):
    return md5(data).hexdigest()
