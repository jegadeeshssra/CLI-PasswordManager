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
        hashed_master_password = HashingService.generate_auth_hash(master_password)
        KEK_binary_salt = KeyService.generate_data_encrypt_key()
        user_data = UserData( email = email, hashed_master_password = master_password, KEK = (base64.b64encode(KEK_binary_salt)).decode("utf-8"))

        response = requests.post(f'{URL}/auth/register',json=user_data)

        res_body = response.json() # json to dict
        if response.status_code == 200:
            if KeyService.process_and_store_DEK(master_password, KEK_binary_salt)
                print("------You are REGISTERED------")
            else:
                raise "Error in processing DEK"
        else:
            print("------------------------------")
            print(res_body["detail"])
            print("------------------------------")
    except ValidationError as e:
        print(f"❌ Validation error: {e.errors()[0]['msg']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return 1

def login() -> str(Optional):
    try:
        email    = input("Enter the email : ") 
        master_password = input("Enter the Master Password : ")

        # Validate email and password
        login_data = UserLoginData(email = email)
        print(type(login_data)) # custom class which is NON JSON serializable
        response = requests.post(f"{URL}/auth/login",json=login_data.model_dump())      # model_dump() - converts the pydantic class type to dictionary
        #print(response.json()) # Type(if empty) - <class 'requests.models.Response'>
        #print(response.json().get("message","Login Failed")) # response.json(): Parses the JSON response from the server into a Python dictionary
        res_body = response.json() # json to dict
        print(res_body) # keys - 'userid' , 'hashed_master_password', 'KEK_salt'
        if HashingService.verify_auth_hash( master_password, res_body["hashed_master_password"]) :
            print("------You are LOGGED IN------")
            return {
                "userid" : res_body["userid"],
                "master_password" : master_password,
                "KEK_salt" : res_body["KEK_salt"]
            }
        elif "detail" in res_body:
            print("------------------------------")
            print(res_body["detail"])
            print("------------------------------")
        else:
            print("------------------------------")
            print("Invalid Credentials")
            print("------------------------------")
        return False
    except ValidationError as e:
        print(f"❌ Validation error: {e.errors()[0]['msg']}")
    except Exception as e:
        print(f"❌ Error: {e}")
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

def user_main(confid_user_data: dict):
    user_functions = UserFunctions(confid_user_data)
    while True:
        initial_option = user_homepage()
        if initial_option == 1:
            user_functions.show_passwords()
        elif initial_option == 2:
            user_functions.add_password()
        elif initial_option == 3:
            user_functions.update_password()
        elif initial_option == 4:
            user_functions.delete_password()
        else:
            print("Exiting...")
            break


class UserFunctions:
    def __init__(self,confid_user_data: dict):
        self.user_id = confid_user_data["user_id"]
        self.master_password = confid_user_data["master_password"]
        self.KEK_salt = confid_user_data["KEK_salt"]
    
    def show_passwords(self):
        response = requests.get(f"{URL}/user/passwords",json=self.user_id)
        res = response.json()

        # retrieve all the passwords in list wihtin a dictionary

        return
    
    def add_password(self):
        application_name = input("Enter the Application Name (email, website, app) : ")
        app_password = input("Enter the password for the applciation :")

        confid_app_data = EncryptDecryptService.encrypt_app_password(
            self.master_password,
            self.KEK_salt,
            app_password
        )
        confid_app_data["user_id"] = self.user_id
        confid_app_data["application_name"] = application_name

        response = requests.post(f"{URL}/user/passwords",json=confid_app_data.model_dump())
        response.json()
        if response.status_code == 200:
            return True
        elif response.status_code == 400:
            choice = input("Application is already used. Do you want to replace the password for same application ?? yes/y OR no/n")
            if choice.lower() in ["y","yes"]:
                confid_app_data["replace"] = "yes"
                second_res = requests.post(f"{URL}/user/passwords",json = confid_app_data.model_dump())
                second_res.json()
                if second_res.status_code == 503:
                    print("Password has been added")
                    return True
                else:
                    print(f"{second_res.detail}")
            else:
                return False
        else:
            print(f"{response.detail}")
            return False
    
    def update_password(self):
        application_name = input("Enter the Application Name to be UPDATED : ")
        app_password = input("Enter the NEW Password for the application :")

        confid_app_data = EncryptDecryptService.encrypt_app_password(
            self.master_password,
            self.KEK_salt,
            app_password
        )
        confid_app_data["user_id"] = self.user_id
        confid_app_data["application_name"] = application_name

        response = requests.update(f"{URL}/user/passwords",json=confid_app_data.model_dump())

----------------------------------------------------------------------------------left here

        return
    
    def delete_password(self):
        return
    



@app.command()
def main():
    while True:
        initial_option = entrypoint()
        
        if(initial_option == 1):
            confid_user_data = login()
            if confid_user_data != 0 :
                user_main(confid_user_data)
        elif(initial_option == 2):
            register()
        else:
            exit()
    return 1

if __name__ == "__main__":
    app()
        