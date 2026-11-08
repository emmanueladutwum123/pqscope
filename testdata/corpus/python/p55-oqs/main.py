import oqs

with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
    public_key = kem.generate_keypair()
