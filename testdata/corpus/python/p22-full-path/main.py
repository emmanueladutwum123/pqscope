import cryptography.hazmat.primitives.asymmetric.ec

key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
    cryptography.hazmat.primitives.asymmetric.ec.SECP521R1()
)
