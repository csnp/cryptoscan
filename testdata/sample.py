# Sample file with cryptographic patterns for testing

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.Cipher import AES, DES

# RSA key generation - quantum vulnerable
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# ECDSA - quantum vulnerable
ec_key = ec.generate_private_key(ec.SECP256R1())

# MD5 - broken hash
def weak_hash(data):
    return hashlib.md5(data).hexdigest()

# SHA-1 - deprecated
def deprecated_hash(data):
    return hashlib.sha1(data).hexdigest()

# AES-ECB - insecure mode
cipher = AES.new(key, AES.MODE_ECB)

# DES - broken
des_cipher = DES.new(key, DES.MODE_CBC)

# TLS 1.0 - deprecated
ssl_context.minimum_version = ssl.TLSv1_0
