"""
vigenere_cipher.py - Vigenère cipher encryption and decryption
"""
def vigenere_encrypt(text: str, key: str) -> str:
    result = []
    key = key.lower()
    key_len = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            k = ord(key[key_index % key_len]) - 97
            if char.isupper():
                result.append(chr((ord(char) - 65 + k) % 26 + 65))
            else:
                result.append(chr((ord(char) - 97 + k) % 26 + 97))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(text: str, key: str) -> str:
    result = []
    key = key.lower()
    key_len = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            k = ord(key[key_index % key_len]) - 97
            if char.isupper():
                result.append(chr((ord(char) - 65 - k) % 26 + 65))
            else:
                result.append(chr((ord(char) - 97 - k) % 26 + 97))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

if __name__ == "__main__":
    msg = input("Enter message: ")
    key = input("Enter key: ")
    enc = vigenere_encrypt(msg, key)
    print(f"Encrypted: {enc}")
    dec = vigenere_decrypt(enc, key)
    print(f"Decrypted: {dec}")
