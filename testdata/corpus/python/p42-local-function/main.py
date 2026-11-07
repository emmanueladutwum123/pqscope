def md5(data):
    return sum(data) % 255


print(md5(b"abc"))
