import os
import hashlib

def xor_cipher(text, key):
    if isinstance(text, str):
        text = text.encode()
    if isinstance(key, str):
        key = key.encode()

    # Key expansion using SHA-256 hashing
    while len(key) < len(text):
        key = hashlib.sha256(key).digest()

    key = key[:len(text)]

    return bytes([x ^ y for x, y in zip(text, key)])

def generate_random_key(length):
    return os.urandom(length)

def encrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        print(f"Read {len(plaintext)} bytes from {input_file}")

        ciphertext = xor_cipher(plaintext, key)
        print(f"Encrypted {len(ciphertext)} bytes")

        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        print(f"File {input_file} encrypted to {output_file}")
    except Exception as e:
        print(f"An error occurred while encrypting the file: {e}")

def decrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
        print(f"Read {len(ciphertext)} bytes from {input_file}")

        plaintext = xor_cipher(ciphertext, key)
        print(f"Decrypted {len(plaintext)} bytes")

        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print(f"File {input_file} decrypted to {output_file}")
    except Exception as e:
        print(f"An error occurred while decrypting the file: {e}")

# Example usage for text encryption/decryption
original_text = "something"
key = generate_random_key(len(original_text))

encrypted = xor_cipher(original_text, key)
print("Encrypted:", encrypted)

decrypted = xor_cipher(encrypted, key)
print("Decrypted:", decrypted.decode())

# Example file encryption/decryption
input_file = 'testing.odt'
output_file = 'encrypted_testing.odt'
decrypted_output_file = 'decrypted_testing.odt'

# Generate a key for file encryption
key_for_file = generate_random_key(32)
print(f"Generated key: {key_for_file}")

# Encrypt the file
encrypt_file(input_file, output_file, key_for_file)

# Decrypt the file
decrypt_file(output_file, decrypted_output_file, key_for_file)

