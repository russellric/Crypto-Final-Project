from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class Main():

    #receivers public key:
    key = RSA.generate(2048)
    publicKey = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(publicKey)
    file_out.close()

    AES_key = get_random_bytes(16)
    cipher = AES.new(AES_key, AES.MODE_EAX)

    # Encrypt the AES key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    enc_session_key = cipher_rsa.encrypt(AES_key)
    #print("Encrypted Session Key:", enc_session_key.hex())

    # Load the message from the file
    file_path = "message.txt"
    with open(file_path, "r") as file:
        message = file.read()

    # Generate AES key and encrypt the message
    cipher_aes = AES.new(AES_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    #print("Message (Ciphertext):", ciphertext)

    
    with open("encrypted_data.bin", "wb") as encrypted_file:
        encrypted_file.write(enc_session_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(ciphertext)
    
# Load the encrypted AES key, nonce, tag, and ciphertext
    with open("encrypted_data.bin", "rb") as encrypted_file:
        encrypted_session_key = encrypted_file.read(256)
        nonce = encrypted_file.read(16)
        tag = encrypted_file.read(16)
        ciphertext = encrypted_file.read()

    #print("Encrypted Session Key:", encrypted_session_key.hex())
    #print("Nonce:", nonce.hex())
    #print("Tag:", tag.hex())

    # Decrypt the AES key using the private RSA key
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    AES_key = cipher_rsa.decrypt(encrypted_session_key)

    #print("Decrypted AES Key:", AES_key.hex())

    # Decrypt the message using the AES key
    cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    print("Decrypted Message:\n", decrypted_message.decode('utf-8'))

#return "encrypted_data.bin"