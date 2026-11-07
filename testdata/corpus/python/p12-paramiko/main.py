import paramiko

rsa_key = paramiko.RSAKey.generate(bits=3072)
host_key = paramiko.Ed25519Key(filename="/etc/ssh/ssh_host_ed25519_key")
