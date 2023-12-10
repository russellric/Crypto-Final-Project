from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
import os


def save_key_to_file(key, filename):
        with open(filename, 'wb') as file:
                file.write(key)

def load_key_from_file(filename):
        with open(filename, 'rb') as file:
                key = file.read()
        return key

def encrypt_message(message, aes_key):
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return ciphertext, tag

def decrypt_message(ciphertext, tag, aes_key):
        cipher = AES.new(aes_key, AES.MODE_EAX)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_message


def verify_signature(message, signature, public_key):
        h = HMAC.new(public_key, message,SHA256)
        h.update(message)
        try:
                h.verify(signature)
                return True
        except ValueError:
                return False
        

def generate_keys():
        # Step 1: Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        save_key_to_file(public_key, "public_key_receiver.pem")
        save_key_to_file(private_key, "private_key_receiver.pem")
        
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        save_key_to_file(private_key, 'private_key_sender.pem')
        save_key_to_file(public_key, 'public_key_sender.pem')

    

def sender():
        # Step 2: Load public key of the receiver
        public_key_receiver = RSA.import_key(load_key_from_file('public_key_receiver.pem'))
        private_key_sender = RSA.import_key(load_key_from_file("private_key_sender.pem"))
        public_key_sender = RSA.import_key(load_key_from_file("public_key_sender.pem"))

    # Step 3: Generate AES key
        aes_key = get_random_bytes(16)  # 128-bit key for AES

    # Step 4: Read the message from file
        with open('message.txt', 'rb') as file:
                message = file.read()

    # Step 5: Encrypt the message with AES
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        

    # Step 6: Encrypt the AES key with the receiver's public key
        rsa_cipher = PKCS1_OAEP.new(public_key_receiver)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Step 7: Generate Message Authentication Code (MAC)
        #signature = HMAC.new(aes_key, ciphertext, digestmod=SHA256).digest()
        

    # Step 8: Write the transmitted data to a file
        with open('Transmitted_Data', 'wb') as file:
                file.write(ciphertext)
                file.write(tag)
                file.write(encrypted_aes_key)
                #file.write(signature)

def receiver():
        public_key_receiver = RSA.import_key(load_key_from_file('public_key_receiver.pem'))
        public_key_sender = RSA.import_key(load_key_from_file("public_key_sender.pem"))
        private_key_receiver = RSA.import_key(load_key_from_file("private_key_receiver.pem"))
        # Step 2: Read transmitted data from file
               
        with open('Transmitted_Data', 'rb') as file:
                ciphertext = file.read(16)
                tag = file.read(16)
                encrypted_aes_key = file.read(256)
                #signature = file.read(32)
                
        # Step 3: Decrypt the AES key with the receiver's rsa public key
        rsa_cipher = PKCS1_OAEP.new(private_key_receiver)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)

        # Step 4: Verify the signature
        #mac_check = HMAC.new(aes_key, ciphertext, SHA256).digest()
        #if signature != mac_check:
        #        print("MAC does not match")


        # Step 5: Decrypt the message with AES
        decrypted_message = decrypt_message(ciphertext, tag, aes_key)
        print("Decrypted Message:", decrypted_message)


generate_keys()
# Run sender first to generate keys and transmit data
sender()
# Run receiver to receive and decrypt the transmitted data
receiver()
