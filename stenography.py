from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = b'secret data'

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
AES_KEY=input()
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce

stored_text = nonce + tag + ciphertext
cipher = AES.new(key, AES.MODE_ECB)
cipher = AES.new(key, AES.MODE_CBC)
cipher_text = cipher.encrypt(pad(data, AES.block_size))
iv = cipher.iv

decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
plain_text = decrypt_cipher.decrypt(cipher_text)
cipher = AES.new(key, AES.MODE_CFB)
cipher_text = cipher.encrypt(data)
iv = cipher.iv

decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
plain_text = decrypt_cipher.decrypt(cipher_text)
cipher = AES.new(key, AES.MODE_OFB)
cipher_text = cipher.encrypt(data)
iv = cipher.iv

decrypt_cipher = AES.new(key, AES.MODE_OFB, iv=iv)
plain_text = decrypt_cipher.decrypt(cipher_text)
cipher = AES.new(key, AES.MODE_CTR)
cipher_text = cipher.encrypt(data)
nonce = cipher.nonce

decrypt_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
plain_text = decrypt_cipher.decrypt(cipher_text)
header = b"header"

#Encryption
cipher = AES.new(key, AES.MODE_GCM)
cipher.update(header)

cipher_text, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce

#Decryption
decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypt_cipher.update(header)

plain_text = decrypt_cipher.decrypt_and_verify(cipher_text, tag)
header = b"header"

#Encryption
cipher = AES.new(key, AES.MODE_EAX)
cipher.update(header)

cipher_text, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce

#Decryption
decrypt_cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypt_cipher.update(header)

plain_text = decrypt_cipher.decrypt_and_verify(cipher_text, tag)
print("Original message: ", data)
print("Encrypted message: ", ciphertext)
print("Decrypted message: ", plain_text)
