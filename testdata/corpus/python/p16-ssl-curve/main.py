import ssl

ctx = ssl.create_default_context()
ctx.set_ecdh_curve("prime256v1")
