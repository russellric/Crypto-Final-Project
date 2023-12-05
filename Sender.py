from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Sender's public key
secret_code = "supersecretspycode"  # RSA key
sender_key = RSA.generate(2048)
encrypted_key = sender_key.export_key(passphrase=secret_code, pkcs=8,
                                      protection="scryptAndAES128-CBC")
print("Sender's Public Key:", encrypted_key.decode("utf-8"), "\n")

# Load the message from the file
file_path = "message.txt"
with open(file_path, "r") as file:
    message = file.read()

# Generate AES key and encrypt the message
AES_key = get_random_bytes(16)
cipher = AES.new(AES_key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
print("Message (Ciphertext):", ciphertext)

# Save the AES key for later decryption
with open("AES_key.bin", "wb") as aes_key_file:
    aes_key_file.write(AES_key)

# Encrypt the AES key with the public RSA key
recipient_public_key = sender_key.publickey()  # Use the public key here
cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
enc_session_key = cipher_rsa.encrypt(AES_key)
print("Encrypted Session Key:", enc_session_key.hex())

with open("encrypted_data.bin", "wb") as encrypted_file:
    encrypted_file.write(enc_session_key)
    encrypted_file.write(cipher.nonce)
    encrypted_file.write(tag)
    encrypted_file.write(ciphertext)

# Now you can send 'enc_session_key', 'ciphertext', and 'tag' to the receiver
# Receiver.global_receive(encrypted_key, enc_session_key, "Its me. proof? I said so")