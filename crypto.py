from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_key(size):
    return get_random_bytes(size)

def encrypt(input_file_path):
    buffer_size = 65536 # 64kb
    key = generate_key(32)
    input_file = open(input_file_path, 'rb')
    output_file = open(input_file_path + '.enc', 'wb')
    cipher_encrypt = AES.new(key, AES.MODE_CBC)
    output_file.write(cipher_encrypt.iv)
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        ciphered_bytes = cipher_encrypt.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)
    input_file.close()
    output_file.close()
    return key

def decrypt(input_file_path, key):
    buffer_size = 65536 # 64kb
    input_file = open(input_file_path, 'rb')
    output_file = open(input_file_path.replace('.enc',''), 'wb')
    iv = input_file.read(16)
    cipher_encrypt = AES.new(key, AES.MODE_CBC, iv=iv)
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        decrypted_bytes = cipher_encrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)
    input_file.close()
    output_file.close()

