from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
            file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
            key = file.read()
    return key

def generate_keys():
    # Step 1: Generate RSA key pair
    #RECEIVER KEYS
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    save_key_to_file(public_key, "public_key_receiver.pem")
    save_key_to_file(private_key, "private_key_receiver.pem")

    #SENDER KEYS
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    save_key_to_file(private_key, 'private_key_sender.pem')
    save_key_to_file(public_key, 'public_key_sender.pem')

def sender():
    #open the message file
    with open('message.txt', 'rb') as file:
        message = file.read()
    data = message
    
    #sender knows and uses these keys
    recipient_key = RSA.import_key(load_key_from_file("public_key_receiver.pem"))
    private_key_sender = RSA.import_key(load_key_from_file("private_key_sender.pem"))
    aes_key = get_random_bytes(16)

    # Encrypt the aes key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Encrypt the data with the AES aes key
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    #hmac signature
    h = HMAC.new(aes_key, digestmod=SHA256)
    h.update(message)

    # write to file
    #TODO: ADD HMAC TO FILE
    with open("Transmitted_Data", "wb") as file:
        file.write(enc_aes_key)
        file.write(cipher_aes.nonce)
        file.write(tag)
        file.write(ciphertext)

    print("Encrypted")

def receiver():
    file_in = open("Transmitted_Data", "rb")

    private_key = RSA.import_key(load_key_from_file("private_key_receiver.pem"))

    #TODO: GET HMAC FROM FILE
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

generate_keys()
sender()
receiver()