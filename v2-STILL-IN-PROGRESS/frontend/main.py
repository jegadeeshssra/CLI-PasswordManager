# from db_connection import get_database_connection
# from hash_and_enc import hash_generation , encrypt_AES_GCM , decrypt_AES_GCM , str_to_bytes, bytes_to_str ,str_to_rawBytes ,rawBytes_to_str
# from login_and_register import login , register
# import base64
import typer
from Crypto.Cipher import AES
import scrypt, os, binascii, argon2
from models.user import UserData , UserPasswordData
from pydantic import ValidationError
# import re , uuid , time , random
app = typer.Typer()

import requests

URL = "http://localhost:8000"
def entrypoint() -> int:
    while True:
        try:
            print("Welcome to the Password Store \n 1 - Login\n 2 - Register\n 3 - EXIT")
            initial_option = int(input("Enter the Option : "))
            if( 0 < initial_option < 4 ):
                break
            else:
                raise ValueError("Choose the given options")
        except ValueError:
            print("------RETRY - Invalid Input-------")
    return initial_option

def register() -> bool:
    try:
        email    = input("Enter the email : ") 
        master_password = input("Enter the Master Password : ")

        user_data = UserData( email = email, master_password = master_password)

        response = requests.post(f'{URL}/auth/register',json=user_data)
        res_body = response.json() # json to dict
        if response.status_code == 200:
            print("------You are REGISTERED------")
        else:
            print("------------------------------")
            print(res_body["detail"])
            print("------------------------------")
            print()
            print()
    except ValidationError as e:
        print(f"❌ Validation error: {e.errors()[0]['msg']}")
        print()
        print()
    except Exception as e:
        print(f"❌ Error: {e}")
        print()
        print()
    return 1

def login() -> str(Optional):
    try:
        email    = input("Enter the email : ") 
        master_password = input("Enter the Master Password : ")

        # Validate email and password
        login_data = UserData(email=email,master_password=master_password)
        print(type(login_data)) # custom class which is NON JSON serializable
        response = requests.post(f"{URL}/auth/login",json=login_data.model_dump())      # model_dump() - converts the pydantic class type to dictionary
        #print(response.json()) # Type(if empty) - <class 'requests.models.Response'>
        #print(response.json().get("message","Login Failed")) # response.json(): Parses the JSON response from the server into a Python dictionary
        res_body = response.json() # json to dict
        print(res_body) # keys - 'userid' , 'detail'
        if response.status_code == 200:
            print("------You are LOGGED IN------")
        else:
            print("------------------------------")
            print(res_body["detail"])
            print("------------------------------")
            print()
            print()
        return res_body["userid"]
    except ValidationError as e:
        print(f"❌ Validation error: {e.errors()[0]['msg']}")
        print()
        print()
    except Exception as e:
        print(f"❌ Error: {e}")
        print()
        print()
    return 0

def user_homepage() -> int:
    while True:
        try:
            print(f"Lets store your passwords \n 1 - SHOW Passwords\n 2 - ADD Password\n 3 - UPDATE Password\n 4 - DELETE Password\n 5 - EXIT")
            initial_option = int(input("Enter the Option : "))
            if( 0 < initial_option < 6 ):
                #print(f"{initial_option}")
                break
            else:       
                raise ValueError("Choose the given options")
        except ValueError:
            print("------RETRY - Invalid Input-------")
    return initial_option

def user_main(user_id: str):
    while True:
        user_functions = UserFunctions(user_id)
        initial_option = user_homepage(user_id)
        if initial_option == 1:
            user_functions(initial_option)
        elif:
            return 1

class EncryptDecryptService:
    @staticmethod
    def generate_random_salt() -> bytes:
        return os.urandom(32)

    @staticmethod
    def generate_data_encrypt_key() -> bytes:
        return os.urandom(32)
    
    @staticmethod
    def generate_auth_hash(master_password: str):
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
    def verify_auth_hash(master_password: str, auth_hash: str):
        argon2Hasher = argon2.PasswordHasher(
            time_cost=15, 
            memory_cost=2**15, 
            parallelism=2, 
            hash_len=32, 
            salt_len=32
            )
        verifyValid = argon2Hasher.verify(auth_hash, master_password)
        return verifyValid

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
    def key_storage(key_encrypt_key: str, ciphertext: bytes, kdf_salt: bytes, nonce: bytes, auth_tag: bytes):








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

class UserFunctions:
    def __init__(self,user_id: str):
        self.user_id = user_id
    
    def show_passwords(self):
        response = requests.get(f"{URL}/user/passwords",json=self.user_id)
        res = response.json()
        # retrieve all the passwords in list wihtin a dictionary

        return
    
    def add_password(self):
        application_name = input("Enter the Application Name (email, website, app) : ")
        app_password = input("Enter the password for the applciation :")
        app_data = UserPasswordData(
            application_name=application_name,
            app_password=app_password 
            )
        response = requests.post(f"{URL}/user/passwords",json=app_data.model_dump())
        return
    
    def update_password(self):
        return
    
    def delete_password(self):
        return
    



@app.command()
def main():
    while True:
        initial_option = entrypoint()
        
        if(initial_option == 1):
            userid = login()
            if user_id != 0 :
                user_main(user_id)

        elif(initial_option == 2):
            register()
        else:
            exit()
    return 1

if __name__ == "__main__":
    app()
