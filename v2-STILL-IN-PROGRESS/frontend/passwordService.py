import argon2 , os
from Crypto.Cipher import AES
import binascii , base64 , scrypt 

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
    def bytes_to_str(raw_binary: bytes) -> str:
        return (base64.b64encode(raw_binary)).decode("utf-8")
    
    @staticmethod
    def str_to_bytes(text: str) -> bytes:
        return base64.b64decode(text.encode("utf-8"))

    @staticmethod
    def generate_key_encrypt_key(master_password: str, salt: bytes) -> str:
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
            KEK.encode("utf-8")
        )
        ( raw_kdf_salt , raw_DEK_ciphertext , raw_nonce , raw_auth_tag ) = encrypted_msg

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

        # json only accepts string
        key_data = {
            #"user_id": 1,
            "DEK_ciphertext" : KeyService.bytes_to_str(raw_DEK_ciphertext),
            "kdf_parameters" : {
                "kdf_salt" : KeyService.bytes_to_str(raw_kdf_salt),
                "nonce" : KeyService.bytes_to_str(nonce),
                "auth_tag" : KeyService.bytes_to_str(auth_tag)
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
    def encrypt_app_password(master_password: str, KEK_salt: str, app_password: str) -> dict:
        # Gnerate the same KEK using master_password and salt
        raw_KEK_salt = KeyService.str_to_bytes(KEK_salt)
        KEK = KeyService.generate_key_encrypt_key(master_password,raw_KEK_salt) # str
        # Retrieve the DEK_ciphertext and OTHER Params for decrypting the ciphertext to get DEK
        user_config = KeyService.retrieve_DEK()
        DEK = EncryptDecryptService.decrypt_AES_GCM(
            KEK.encode("utf-8"),
            user_config["kdf_parameters"]["kdf_salt"],
            user_config["DEK_ciphertext"],
            user_config["kdf_parameters"]["nonce"],
            user_config["kdf_parameters"]["auth_tag"]
        )

        encrypted_msg = EncryptDecryptService.encrypt_AES_GCM(
            app_password,
            KeyService.str_to_bytes(DEK)
            )
        ( kdf_salt , app_pwd_ciphertext , nonce , auth_tag ) = encrypted_msg
        return {
            "app_password_ciphertext" : KeyService.bytes_to_str(app_pwd_ciphertext),
            "kdf_salt" : KeyService.bytes_to_str(kdf_salt),
            "nonce" : KeyService.bytes_to_str(nonce),
            "auth_tag" : KeyService.bytes_to_str(auth_tag)
        }

    @staticmethod
    def decrypt_app_password(master_password: str, KEK_salt: str, app_password_ciphertext: str, kdf_salt: str, nonce: str, auth_tag: str) -> str:
        # Generate the same KEK using master_password and salt
        raw_KEK_salt = KeyService.str_to_bytes(KEK_salt)
        KEK = KeyService.generate_key_encrypt_key(master_password,raw_KEK_salt) # str
        # Retrieve the DEK_ciphertext and OTHER Params for decrypting the ciphertext to get DEK
        user_config = KeyService.retrieve_DEK()
        DEK = EncryptDecryptService.decrypt_AES_GCM(
            KEK.encode("utf-8"),
            user_config["kdf_parameters"]["kdf_salt"],
            user_config["DEK_ciphertext"],
            user_config["kdf_parameters"]["nonce"],
            user_config["kdf_parameters"]["auth_tag"]
        )

        decrypted_msg = EncryptDecryptService.decrypt_AES_GCM(
            KeyService.str_to_bytes(DEK),
            KeyService.str_to_bytes(kdf_salt),
            KeyService.str_to_bytes(app_password_ciphertext),
            KeyService.str_to_bytes(nonce),
            KeyService.str_to_bytes(auth_tag)
        )
        return decrypted_msg

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
