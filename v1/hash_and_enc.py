import base64 , bcrypt
from Crypto.Cipher import AES
import binascii , os , scrypt


def hash_generation( password: str, binary_salt: str ):
    # Some functions (like hashing, encryption, or KDFs) specifically require binary data because they operate at 
    #   the byte level.
    binary_password = password.encode('utf-8') # String to binary data
    binary_key = bcrypt.kdf(    # Produce the key in binary format 
        password=binary_password,
        salt=binary_salt,
        desired_key_bytes=32,
        rounds=100
    )

    base64_key_bytes = base64.b64encode(binary_key) # converts normal binary data into base64 encoded binary data
    base64_key_string = base64_key_bytes.decode("utf-8")
    #print(f"Base64 key byte string - {base64_key_bytes}")
    # print(f"Base64 key byte string - {type(base64_key_bytes)}")
    print(f"Base64 encoded Key String - {base64_key_string}")
    # print(f"Base64 encoded Key String - {type(base64_key_string)}")
                                            # raw binary data -> base64 encoded binary -> utf-8 decoded string
    return { "key" : base64_key_string, "salt" : (base64.b64encode(binary_salt)).decode("utf-8") }

def str_to_bytes(text: str):
    return text.encode("ascii")

def bytes_to_str(encoded_bytes_string: bytes):
    return encoded_bytes_string.decode("ascii")

def str_to_rawBytes(text: str):
    return base64.b64decode(text.encode("ascii"))

def rawBytes_to_str(raw_bytes: bytes):
    return base64.b64encode(raw_bytes).decode("ascii")

def encrypt_AES_GCM( plaintext: bytes, login_password_hash : bytes):
    kdf_salt = os.urandom(16)
    secret_key = scrypt.hash(login_password_hash, kdf_salt, N=16384, r=8, p=1, buflen=32)
    aes_cipher = AES.new(secret_key , AES.MODE_GCM)
    ciphertext , auth_tag = aes_cipher.encrypt_and_digest(plaintext)
    return ( kdf_salt , ciphertext , aes_cipher.nonce , auth_tag)

def decrypt_AES_GCM( login_password_hash: bytes,    
    secret_key = scrypt.hash(login_password_hash,kdf_salt,N=16384,r=8,p=1,buflen=32)
    aes_cipher = AES.new(secret_key , AES.MODE_GCM , IV)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext,auth_tag)
    return plaintext 




# This Python script demonstrates **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)** encryption and decryption. Below is a **line-by-line technical explanation** of the code:

# ---

# ### 1. **Importing Required Modules**
# ```python
# from Crypto.Cipher import AES
# import binascii, os
# ```
# - **`Crypto.Cipher`**: Provides cryptographic functionalities, including AES encryption.
# - **`binascii`**: Used for converting binary data to hexadecimal representation (and vice versa).
# - **`os`**: Provides a function (`os.urandom`) to generate cryptographically secure random bytes.

# ---

# ### 2. **Encryption Function**
# ```python
# def encrypt_AES_GCM(msg, secretKey):
#     aesCipher = AES.new(secretKey, AES.MODE_GCM)
#     ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
#     return (ciphertext, aesCipher.nonce, authTag)
# ```

# #### Explanation:
# - **`def encrypt_AES_GCM(msg, secretKey)`**:
#   - Defines a function to encrypt a message using AES-GCM.
#   - Takes two arguments: `msg` (the plaintext message) and `secretKey` (the encryption key).

# - **`aesCipher = AES.new(secretKey, AES.MODE_GCM)`**:
#   - Creates a new AES cipher object in GCM mode.
#   - `secretKey`: The encryption key (must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256, respectively).
#   - `AES.MODE_GCM`: Specifies the GCM mode, which provides both encryption and authentication.

# - **`ciphertext, authTag = aesCipher.encrypt_and_digest(msg)`**:
#   - Encrypts the message and generates an authentication tag.
#   - `ciphertext`: The encrypted message.
#   - `authTag`: The authentication tag used to verify the integrity of the ciphertext.

# - **`return (ciphertext, aesCipher.nonce, authTag)`**:
#   - Returns a tuple containing:
#     - `ciphertext`: The encrypted message.
#     - `aesCipher.nonce`: A unique value used during encryption (required for decryption).
#     - `authTag`: The authentication tag.

# ---

# ### 3. **Decryption Function**
# ```python
# def decrypt_AES_GCM(encryptedMsg, secretKey):
#     (ciphertext, nonce, authTag) = encryptedMsg
#     aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
#     plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
#     return plaintext
# ```

# #### Explanation:
# - **`def decrypt_AES_GCM(encryptedMsg, secretKey)`**:
#   - Defines a function to decrypt a message encrypted with AES-GCM.
#   - Takes two arguments: `encryptedMsg` (a tuple containing ciphertext, nonce, and authTag) and `secretKey` (the encryption key).

# - **`(ciphertext, nonce, authTag) = encryptedMsg`**:
#   - Unpacks the tuple `encryptedMsg` into its components:
#     - `ciphertext`: The encrypted message.
#     - `nonce`: The unique value used during encryption.
#     - `authTag`: The authentication tag.

# - **`aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)`**:
#   - Creates a new AES cipher object in GCM mode using the same `secretKey` and `nonce` used during encryption.

# - **`plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)`**:
#   - Decrypts the ciphertext and verifies its integrity using the `authTag`.
#   - If the authentication tag is invalid, it raises an exception (indicating tampering or corruption).

# - **`return plaintext`**:
#   - Returns the decrypted plaintext message.

# ---

# ### 4. **Generating a Secret Key**
# ```python
# secretKey = os.urandom(32)  # 256-bit random encryption key
# ```
# - **`os.urandom(32)`**:
#   - Generates 32 random bytes (256 bits), which is the required key size for AES-256.
#   - The key is cryptographically secure and suitable for encryption.

# ---

# ### 5. **Printing the Encryption Key**
# ```python
# print("Encryption key:", binascii.hexlify(secretKey))
# ```
# - **`binascii.hexlify(secretKey)`**:
#   - Converts the binary `secretKey` to a hexadecimal string for readability.
# - **`print`**:
#   - Displays the encryption key in hexadecimal format.

# ---

# ### 6. **Encrypting a Message**
# ```python
# msg = b'Message for AES-256-GCM + Scrypt encryption'
# encryptedMsg = encrypt_AES_GCM(msg, secretKey)
# print("encryptedMsg", {
#     'ciphertext': binascii.hexlify(encryptedMsg[0]),
#     'aesIV': binascii.hexlify(encryptedMsg[1]),
#     'authTag': binascii.hexlify(encryptedMsg[2])
# })
# ```

# #### Explanation:
# - **`msg = b'Message for AES-256-GCM + Scrypt encryption'`**:
#   - Defines the plaintext message as a byte string (`b''`).

# - **`encryptedMsg = encrypt_AES_GCM(msg, secretKey)`**:
#   - Calls the `encrypt_AES_GCM` function to encrypt the message.

# - **`print("encryptedMsg", {...})`**:
#   - Displays the encrypted message components in hexadecimal format:
#     - `ciphertext`: The encrypted message.
#     - `aesIV`: The nonce (incorrectly labeled as `aesIV`; it should be `nonce`).
#     - `authTag`: The authentication tag.

# ---

# ### 7. **Decrypting the Message**
# ```python
# decryptedMsg = decrypt_AES_GCM(encryptedMsg, secretKey)
# print("decryptedMsg", decryptedMsg)
# ```

# #### Explanation:
# - **`decryptedMsg = decrypt_AES_GCM(encryptedMsg, secretKey)`**:
#   - Calls the `decrypt_AES_GCM` function to decrypt the message.

# - **`print("decryptedMsg", decryptedMsg)`**:
#   - Displays the decrypted plaintext message.

# ---

# ### Output Example:
# ```plaintext
# Encryption key: b'5f4dcc3b5aa765d61d8327deb882cf99'
# encryptedMsg {
#     'ciphertext': b'2b7e151628aed2a6abf7158809cf4f3c',
#     'aesIV': b'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
#     'authTag': b'cafebabefacedbaddecaf888'
# }
# decryptedMsg b'Message for AES-256-GCM + Scrypt encryption'
# ```

# ---

# ### Summary:
# - The script demonstrates **AES-GCM encryption and decryption**.
# - It uses a **256-bit secret key** for encryption.
# - The **nonce** and **authentication tag** ensure the integrity and authenticity of the encrypted data.
# - The `binascii.hexlify` function is used to display binary data in a human-readable hexadecimal format.

# Let me know if you need further clarification!    