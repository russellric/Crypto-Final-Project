from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256


with open('message.txt', 'rb') as file:
    message = file.read()
data = message

recipient_key = RSA.import_key(open("public_key_receiver.pem").read())
aes_key = get_random_bytes(16)

# Encrypt the aes key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)

# Encrypt the data with the AES aes key
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

#hmac signature
private_key_sender = RSA.import_key(open("private_key_sender.pem","rb").read())
h = HMAC.new(aes_key, digestmod=SHA256)
h.update(message)

# write to file

with open("Transmitted_Data", "wb") as file:
    file.write(enc_aes_key)
    file.write(cipher_aes.nonce)
    file.write(tag)
    file.write(ciphertext)


print("Encrypted")

file_in = open("Transmitted_Data", "rb")

private_key = RSA.import_key(open("private_key_receiver.pem").read())

enc_aes_key, nonce, tag, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
file_in.close()

# Decrypt the aes key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
aes_key = cipher_rsa.decrypt(enc_aes_key)

# Decrypt the data with the AES aes key
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
message = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(message.decode("utf-8"))
