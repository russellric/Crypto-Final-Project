from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()



data = "I met aliens in UFO. Here is the map.".encode("utf-8")
file_out = open("encrypted_data.bin", "wb")

# Encrypt the data with the AES session key
aes_key = get_random_bytes(16)
cipher_aes = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

#Encrypt the aes key with the rsa key
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)

[ file_out.write(x) for x in (enc_aes_key, cipher_aes.nonce, tag, ciphertext) ]
file_out.close()

file_in = open("encrypted_data.bin", "rb")

#private_key = RSA.import_key(open("private.pem").read())

with open("encrypted_data.bin", "wb") as encrypted_file:
        encrypted_file.write(enc_aes_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(ciphertext)
file_in.close()

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(public_key)
session_key = cipher_rsa.decrypt(enc_aes_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, cipher_aes.nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))


