import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

def generate_random_word(min_length=6, max_length=11):
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    length = secrets.randbelow(max_length - min_length + 1) + min_length
    return ''.join(secrets.choice(letters) for _ in range(length))

def generate_passphrase(word_count=20):
    return ' '.join(generate_random_word() for _ in range(word_count))

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)

def decrypt_data(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_file(file_path: str, passphrase: str, output_path: str):
    with open(file_path, "rb") as file:
        file_bytes = file.read()

    file_text = base64.b64encode(file_bytes).decode('utf-8')

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)

    encrypted_text = encrypt_data(key, file_text.encode('utf-8'), nonce)

    if not output_path:
        output_path = os.path.splitext(file_path)[0] + ".val"

    with open(output_path, "wb") as file:
        file.write(salt + nonce + encrypted_text)

def decrypt_file(file_path: str, passphrase: str, output_path: str):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    encrypted_text = encrypted_data[28:]

    key = derive_key(passphrase, salt)
    decrypted_text = decrypt_data(key, encrypted_text, nonce).decode('utf-8')

    decrypted_bytes = base64.b64decode(decrypted_text)

    if not output_path:
        vault_name = os.path.splitext(os.path.basename(file_path))[0]
        extension = os.path.splitext(vault_name)[1]
        output_path = os.path.join(os.path.dirname(file_path), f"{vault_name}.dcrypt{extension}")

    with open(output_path, "wb") as file:
        file.write(decrypted_bytes)

def main():
    choice = input("Choose an option (1 for encrypt, 2 for decrypt): ")
    
    if choice == '1':
        file_path = input("Enter the path to the file you want to encrypt: ")
        output_path = input("Enter the path where you want to save the encrypted file: ")
        passphrase = generate_passphrase()
        encrypt_file(file_path, passphrase, output_path)
        print(f"File encrypted and stored at {output_path if output_path else os.path.splitext(file_path)[0] + '.val'}")
        print(f"Your passphrase is: {passphrase}")
    elif choice == '2':
        file_path = input("Enter the path to the file you want to decrypt: ")
        output_path = input("Enter the path where you want to save the decrypted file: ")
        passphrase = input("Enter the passphrase: ")
        decrypt_file(file_path, passphrase, output_path)
        print(f"File decrypted and stored at {output_path}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()