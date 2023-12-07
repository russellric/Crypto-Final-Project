from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class Receiver:
   
   
    def decrypt_message(encrypted_message, publicKey):        
        
        # Load the encrypted AES key, nonce, tag, and ciphertext
        with open(encrypted_message, "rb") as encrypted_file:
            encrypted_session_key = encrypted_file.read(256)
            nonce = encrypted_file.read(16)
            tag = encrypted_file.read(16)
            ciphertext = encrypted_file.read()

        #print("Encrypted Session Key:", encrypted_session_key.hex())
        #print("Nonce:", nonce.hex())
        #print("Tag:", tag.hex())

        # Decrypt the AES key using the private RSA key
        #cipher_rsa = PKCS1_OAEP.new(receiver_key)
        AES_key = publicKey.decrypt(encrypted_session_key)

        #print("Decrypted AES Key:", AES_key.hex())

        # Decrypt the message using the AES key
        cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

        print("Decrypted Message:\n", decrypted_message.decode('utf-8'))
    