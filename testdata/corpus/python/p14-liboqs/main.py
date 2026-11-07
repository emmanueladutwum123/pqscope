import oqs

with oqs.KeyEncapsulation("ML-KEM-768") as kem:
    public_key = kem.generate_keypair()

with oqs.Signature("ML-DSA-65") as signer:
    signer_public = signer.generate_keypair()
