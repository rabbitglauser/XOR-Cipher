import os
import hashlib

def xor_cipher(text, key):
    """
    :param text: The text to be encrypted or decrypted as a string or bytes object.
    :param key: The encryption or decryption key as a string or bytes object.
    :return: The result of the XOR cipher operation as a bytes object.

    The `xor_cipher` method applies the XOR cipher algorithm to encrypt or decrypt the given text using the provided key. The method supports both string and bytes inputs for the text and key parameters.

    If the text parameter is a string, it will be encoded to bytes using the UTF-8 encoding before performing the XOR cipher operation.

    If the key parameter is a string, it will be encoded to bytes using the UTF-8 encoding before performing the XOR cipher operation.

    The key expansion process is performed using the SHA-256 hashing algorithm. The key is expanded to match the length of the text by repeatedly applying the SHA-256 hashing algorithm to the key until it reaches the desired length.

    After the key expansion, the XOR cipher operation is performed by XORing each byte of the text with the corresponding byte of the key using the zip function. The result is returned as a bytes object.

    Example usage:
        text = "Hello, world!"
        key = "secret"
        encrypted_text = xor_cipher(text, key)
        decrypted_text = xor_cipher(encrypted_text, key)

        assert text == decrypted_text.decode()
    """
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
    """
    Generates a random key.

    :param length: The length of the key.
    :return: A random key of the specified length.
    """
    return os.urandom(length)

def encrypt_file(input_file, output_file, key):
    """
    Encrypts a file using a given key using XOR cipher.

    :param input_file: The path to the input file to encrypt.
    :param output_file: The path to the output file where the encrypted data will be saved.
    :param key: The encryption key.

    :return: None
    """
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
    """
    Decrypts the contents of the input file using the XOR cipher algorithm and saves the decrypted data to the output file.

    :param input_file: Path to the input file to decrypt.
    :param output_file: Path to save the decrypted data.
    :param key: Encryption key used for decryption.
    :return: None
    """
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

