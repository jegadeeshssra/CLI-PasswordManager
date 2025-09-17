import argon2 , os

class HashingService:

    @staticmethod
    def generate_random_salt() -> bytes:
        return os.urandom(32)

    @staticmethod
    def generate_auth_hash(master_password: str) -> str:
        argon2Hasher = argon2.PasswordHasher(
            time_cost=15, 
            memory_cost=2**15, 
            parallelism=2, 
            hash_len=32, 
            salt_len=32
            )
        auth_hash = argon2Hasher.hash(master_password)
        return auth_hash
    
    @staticmethod
    def verify_auth_hash(master_password: str, auth_hash: str) -> bool:
        argon2Hasher = argon2.PasswordHasher(
            time_cost=15, 
            memory_cost=2**15, 
            parallelism=2, 
            hash_len=32, 
            salt_len=32
            )
        verifyValid = argon2Hasher.verify(auth_hash, master_password)
        return verifyValid

class KeyService:

    @staticmethod
    def generate_data_encrypt_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def generate_key_encrypt_key(master_password: str, salt: bytes):
        argon2Hasher = argon2.PasswordHasher(
            time_cost=16, 
            memory_cost=2**15, 
            parallelism=2, 
            hash_len=32, 
            salt_len=16
            )
        # Without the salt parameter, it produces unique hash every single time for the same password
        hash = argon2Hasher.hash(master_password, salt= salt)
        print("Argon2 hash (random salt):", hash)
        # key encryption key
        return hash

    @staticmethod
    def store_KEK(key_encrypt_key: str, DEK_ciphertext: bytes, kdf_salt: bytes, nonce: bytes, auth_tag: bytes):
        app_name = "secure"
        if os.name == 'nt':
            base_dir = Path(os.environ['APPDATA'])
        elif os.name == 'posix':
            base_dir = Path.home()
        else:
            base_dir = Path.cwd()

        app_dir = base_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        config_file = app_dir / "user_config.json"

        print("OS - ",os.name)
        print("AppDIR - ",app_dir)
        print("ConfigFile - ",config_file)

        storage_data = {
            "version": "1.0",
            "user_id": 1,
            "kdf_parameters": {
                "algorithm": "argon2id",
                "time_cost": 16,
                "memory_cost": 32768,  # 32MB 
                "parallelism": 2,
                "hash_len": 32,
                "salt_len": 16
            }
        }

        with open(config_file, 'w') as f:
            json.dump(storage_data,f,indent = 2)

        return True
    
    @staticmethod
    def retrieve_KEK():
        return {
            "key_encrypt_key" : key_encrypt_key,
            "DEK_ciphertext" : DEK_ciphertext,
            "kdf_salt" : kdf_salt,
            "nonce" : nonce,
            "auth_tag" : auth_tag 
        }

class EncryptDecryptService:

    @staticmethod
    def encrypt_AES_GCM( plaintext: str, initial_key: bytes):
        kdf_salt = os.urandom(16)
        secret_key = scrypt.hash(initial_key, kdf_salt, N=16384, r=8, p=1, buflen=32)
        aes_cipher = AES.new(secret_key , AES.MODE_GCM)
        ciphertext , auth_tag = aes_cipher.encrypt_and_digest(plaintext)
        return ( kdf_salt , ciphertext , aes_cipher.nonce , auth_tag)
    
    @staticmethod
    def decrypt_AES_GCM( initial_key: bytes, kdf_salt: bytes, ciphertext: bytes, IV: bytes, auth_tag: bytes ):
        secret_key = scrypt.hash(login_password_hash,kdf_salt,N=16384,r=8,p=1,buflen=32)
        aes_cipher = AES.new(secret_key , AES.MODE_GCM , IV)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext,auth_tag)
        return plaintext 
