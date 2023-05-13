def encrypt(plaintext, key=3):
    # encrypts alphabetic characters by shifting them 3 (based on the key) while leaving
    # non-alphabetic characters unchanged
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            # Checks if the character is alphabetic
            ascii_offset = 65 if char.isupper() else 97
            # determines the ASCII offset based on whether the character is uppercase or
            # lowercase. This offset is used to convert the character to its corresponding
            # index in the alphabet
            encrypted_char = chr((ord(char) - ascii_offset + key) % 26 + ascii_offset)
            # performs the actual encryption process. It subtracts the ASCII offset, adds
            # the encryption key, takes the modulo 26 to handle wraparound, and then adds
            # back the ASCII offset to convert the result back to a character
            ciphertext += encrypted_char
            # appends the encrypted character to the 'ciphertext' string
        else:
            ciphertext += char
    return ciphertext


def decrypt(ciphertext, key=3):
    # reverses the ciphertext by 3 (key)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            decrypted_char = chr((ord(char) - ascii_offset - key) % 26 + ascii_offset)
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext
