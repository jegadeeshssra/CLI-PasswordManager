from Crypto.Cipher import AES
import binascii , os , scrypt

def encryptAES_GCM( msg : bytes , secret_key : bytes ):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM)      # Creates a new AES cipher object in GCM mode.
    ciphertext , auth_tag = aes_cipher.encrypt_and_digest(msg)
    print("type - ",{
        "ciphertext" : type(ciphertext),    
        "IV" : type(aes_cipher.nonce),      
        "hash" : type(auth_tag)             
    })
    return (ciphertext , aes_cipher.nonce , auth_tag )
    # The ciphertext is the encrypted message.
    # The nonce is the randomly generated initial vector (IV) for the GCM construction.
    # The authTag is the message authentication code (MAC) calculated during the encryption.

def decryptAES_GCM( encrypted_msg: tuple , secret_key: bytes):
    ciphertext , IV , auth_tag = encrypted_msg
    aes_cipher = AES.new(secret_key, AES.MODE_GCM , IV)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext,auth_tag)
    return plaintext

def main2()
    secret_key = os.urandom(32)
    print("type(secret key) - ",type(secret_key))                   # 256-bit encryption key
    print("Encrption Key - ",binascii.hexlify(secret_key))          # Hexadecimal Rep of binary secretKey
    plaintext = b'this the app password'                            # Byter string of the sensitive msg
    print("type(msg) -",type(plaintext))

    encrypted_msg = encryptAES_GCM(plaintext,secret_key)
    print("encrypted message - ",{
        'ciphertext': binascii.hexlify(encrypted_msg[0]),
        'IV' : binascii.hexlify(encrypted_msg[1]),
        'hash' : binascii.hexlify(encrypted_msg[2])
    })

    decrypted_msg = decryptAES_GCM(encrypted_msg,secret_key)
    print("Decrypted Msg - ",decrypted_msg)


def encrypt_AES_GCM( plaintext: bytes , password: bytes):
    kdf_salt = os.urandom(16)
    secret_key = scrypt.hash(password, kdf_salt, N=16384, r=8, p=1, buflen=32)
    aes_cipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext , auth_tag = aes_cipher.encrypt_and_digest(plaintext) 
    print("type - ",{
        "kdf_salt" : type(kdf_salt),        
        "ciphertext" : type(ciphertext),    
        "IV" : type(aes_cipher.nonce),      
        "hash" : type(auth_tag)             
    })
    return (kdf_salt , ciphertext , aes_cipher.nonce , auth_tag)

def decrypt_AES_GCM( encrypted_text: tuple , password: bytes):
    (kdf_salt , ciphertext , IV , auth_tag ) = encrypted_text
    secret_key = scrypt.hash(password, kdf_salt , N=16384, r=8, p=1, buflen=32)
    aes_cipher = AES.new(secret_key, AES.MODE_GCM, IV)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext,auth_tag)
    return plaintext

def main():
    plaintext = b'Tonight is IPL 2025 Opening Night'
    password = b'secret-code-here-bruh'

    encrypted_text = encrypt_AES_GCM(plaintext,password)
    print("encrypted message - ",{
        'kdf_salt': binascii.hexlify(encrypted_text[0]),
        'ciphertext': binascii.hexlify(encrypted_text[1]),
        'IV' : binascii.hexlify(encrypted_text[2]),
        'hash' : binascii.hexlify(encrypted_text[3])
    })

    decrypted_text = decrypt_AES_GCM(encrypted_text,password)
    print("Plaintext -",decrypted_text)

main()




    

