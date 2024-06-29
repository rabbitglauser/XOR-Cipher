def xor_cipher(text, key):
    """
    :param text: The text to be encrypted or decrypted using the XOR cipher.
    :param key: The key used for encryption or decryption.
    :return: The result of the XOR cipher operation as bytes.

    """
    if isinstance(text, str):
        text = text.encode()

    while len(key) < len(text):
        key += bytes(key)

    key = key[:len(text)]

    return bytes([x ^ y for x, y in zip(text, key)])


original_text = "something"

key = b'secret'

encrypted = xor_cipher(original_text, key)
print(encrypted)

decrypted = xor_cipher(encrypted, key)
print(decrypted.decode())
