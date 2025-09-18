import argon2 , os
import binascii , base64

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
    def process_and_store_DEK(master_password: str, KEK_binary_salt: bytes):
        
        # Generating KEK using KDF
        KEK = KeyService.generate_key_encrypt_key(
            master_password, 
            KEK_binary_salt
            )
        # Generating DEK 
        DEK_raw_bytes =  KeyService.generate_data_encrypt_key()
        # Ecrypting DEK with KEK as key
        encrypted_msg = EncryptDecryptService.encrypt_AES_GCM(
            (base64.b64encode(DEK_raw_bytes)).decode("utf-8"),
            KEK
        )
        ( kdf_salt , DEK_ciphertext , nonce , auth_tag ) = encrypted_msg

        app_name = ".secure_app"
        if os.name == 'nt':
            base_dir = Path(os.environ['USERPROFILE'])
        elif os.name == 'posix':
            base_dir = Path.home()
        else:
            base_dir = Path.cwd()

        app_dir = base_dir / app_name
        if not Path(app_dir).exists():
            app_dir.mkdir(parents=True, exist_ok=True)
        config_file = app_dir / "user_config.json"
        #config_file = app_dir / f"user_config_{userid}.json"

        print("OS - ",os.name)
        print("AppDIR - ",app_dir)
        print("ConfigFile - ",config_file)

        key_data = {
            #"user_id": 1,
            "DEK_ciphertext" : DEK_ciphertext,
            "kdf_parameters" : {
                "kdf_salt" : kdf_salt,
                "nonce" : nonce,
                "auth_tag" : auth_tag
            }
        }
        for open(config_file,'w') as f:
            json.dump(key_data,f,indent = 2)
        return True
    
    @staticmethod
    def retrieve_DEK() -> dict:
        app_name = ".secure_app"
        if os.name == 'nt':
            base_dir = Path(os.environ['USERPROFILE'])
        elif os.name == 'posix':
            base_dir = Path.home()
        else:
            base_dir = Path.cwd()

        app_dir = base_dir / app_name
        config_file = app_dir / "user_config.json"
        #config_file = app_dir / f"user_config_{userid}.json"

        print("OS - ",os.name)
        print("AppDIR - ",app_dir)
        print("ConfigFile - ",config_file)

        if not config_file.exists():
            raise FileNotFoundError("No stored encryption keys found")

        with open(config_file, 'r') as f:
            key_data = json.load(f)

        return key_data

class EncryptDecryptService:

    @staticmethod
    def encrypt_app_password(master_password: str, KEK_salt: str, app_password: str):
        # Gnerate the same KEK using master_password and salt
        raw_KEK_salt = base64.b64decode((KEK_salt).encode("utf-8"))
        raw_KEK = KeyService.generate_key_encrypt_key(master_password,raw_KEK_salt) # str
        # Retrieve the DEK_ciphertext and OTHER Params for decrypting the ciphertext to get DEK
        raw_user_config = KeyService.retrieve_DEK()
        DEK = EncryptDecryptService.decrypt_AES_GCM(
            raw_KEK,
            raw_user_config["kdf_parameters"]["kdf_salt"],
            raw_user_config["DEK_ciphertext"],
            raw_user_config["kdf_parameters"]["nonce"],
            raw_user_config["kdf_parameters"]["auth_tag"]
        )

        encrypted_msg = EncryptDecryptService.encrypt_AES_GCM(
            app_password,
            DEK
            )
        ( kdf_salt , app_pwd_ciphertext , nonce , auth_tag ) = encrypted_msg
        return {
            "app_password_ciphertext" : app_pwd_ciphertext,
            "kdf_salt" : kdf_salt,
            "nonce" : nonce,
            "auth_tag" : auth_tag
        }


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
