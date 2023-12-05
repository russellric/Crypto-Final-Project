# Cryptography Final Project
# Russell Rickards
# Isabela Kenton

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
#from distutils import file_util

#Receivers's public key
secret_code = "supersecretspycode" #RSA key
key = RSA.generate(2048)
encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

print(encrypted_key)

#AES private key
#key = get_random_bytes(16)
#cipher = AES.new
