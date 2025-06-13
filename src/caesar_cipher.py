"""
caesar_cipher.py - Caesar cipher encryption and decryption
"""
def caesar_encrypt(text: str, shift: int) -> str:
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        elif char.islower():
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)

if __name__ == "__main__":
    msg = input("Enter message: ")
    s = int(input("Enter shift: "))
    enc = caesar_encrypt(msg, s)
    print(f"Encrypted: {enc}")
    dec = caesar_decrypt(enc, s)
    print(f"Decrypted: {dec}")
