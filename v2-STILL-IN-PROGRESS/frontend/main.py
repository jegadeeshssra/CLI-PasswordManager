import typer
# import re , uuid , time , random
from Crypto.Cipher import AES
import scrypt, os, binascii, argon2 , base64
from pydantic import ValidationError
from typing import Optional

# from other programs
from models.user import UserData , UserPasswordData , UserLoginData
from passwordService import HashingService , KeyService , EncryptDecryptService

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
        user_data = UserData( email = email, hashed_master_password = hashed_master_password, KEK_salt = (base64.b64encode(KEK_binary_salt)).decode("utf-8"))

        response = requests.post(f'{URL}/auth/register',json=user_data.model_dump())

        res_body = response.json() # json to dict
        if response.status_code == 200:
            if KeyService.process_and_store_DEK(email, master_password, KEK_binary_salt):
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

def login() -> Optional[str]:
    try:
        email    = input("Enter the email : ") 
        master_password = input("Enter the Master Password : ")

        # Validate email and password
        login_data = UserLoginData(email = email)
        # print(type(login_data)) # custom class which is NON JSON serializable
        response = requests.post(f"{URL}/auth/login",json=login_data.model_dump())      # model_dump() - converts the pydantic class type to dictionary
        #print(response.json()) # Type(if empty) - <class 'requests.models.Response'>
        #print(response.json().get("message","Login Failed")) # response.json(): Parses the JSON response from the server into a Python dictionary
        res_body = response.json() # json to dict
        #print(res_body) # keys - 'userid' , 'hashed_master_password', 'KEK_salt'
        if response.status_code == 200:
            if HashingService.verify_auth_hash( master_password, res_body["hashed_master_password"]) :
                print("------You are LOGGED IN------")
                return {
                    "user_id" : res_body["userid"],
                    "master_password" : master_password,
                    "KEK_salt" : res_body["KEK_salt"]
                }
            else:
                print("------------------------------")
                print("Invalid Credentials")
                print("------------------------------")
        else:
            print("------------------------------")
            print(res_body["detail"])
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
    return 1


class UserFunctions:
    def __init__(self,confid_user_data: dict):
        self.user_id = confid_user_data["user_id"]
        self.master_password = confid_user_data["master_password"]
        self.KEK_salt = confid_user_data["KEK_salt"]

    def show_passwords(self):
        try: 
            response = requests.get(f"{URL}/user/passwords",params={"userid": self.user_id })
            res = response.json()
            if response.status_code != 200:
                print(f"-------------------{res["detail"]}------------------------")
                return False
            else:
                rows = res["data"] # [[entryid, userid, application_name, salt, app_password, iv, auth_tag]]
            # retrieve all the passwords in list within a dictionary
            no_of_passwords = len(rows)
            #print(rows)
            while(True):
                try:
                    print("Available applications:")
                    # entryid|userid|application_name|salt|app_password|iv|auth_tag
                    for i in range(0,no_of_passwords):
                        print(f"{i} - {rows[i][2]}")    # 2 - application_name
                    print(f"{no_of_passwords} - EXIT")

                    option = int(input("\nEnter the App number to reveal that password : "))
                    if option >= 0 and option < no_of_passwords:
                        print(f"Application - {rows[option][2]}")
                        decrypted_msg = EncryptDecryptService.decrypt_app_password(
                            self.master_password,
                            self.KEK_salt,
                            rows[option][4],    # 4 - app_password
                            rows[option][3],    # 3 - salt
                            rows[option][5],    # 5 - iv
                            rows[option][6]     # 6 - auth_tag
                        )
                        print(f"Password - {decrypted_msg}")
                        
                    elif option == no_of_passwords:
                        break
                    else:       
                        print("Enter a Valid Option")
                except TypeError as e:
                    print(f"❌ Type error: {e}")
                    print("Enter a Valid Option")
        except Exception as e:
            print(f"❌ Error: {e}")
        return 1
    
    def add_password(self):
        application_name = input("Enter the Application Name (email, website, app) : ")
        app_password = input("Enter the password for the applciation :")

        confid_app_data = EncryptDecryptService.encrypt_app_password(
            self.master_password,
            self.KEK_salt,
            app_password
        )
        confid_app_data["userid"] = self.user_id
        confid_app_data["application_name"] = application_name
        print()
        response = requests.post(
            f"{URL}/user/passwords",
            json=confid_app_data
            )
        res = response.json()
        if response.status_code == 200:
            print("----------------------Password has been added-----------------------------")
            return True
        elif response.status_code == 400:
            choice = input("Application is already used. Do you want to replace the password for same application ?? yes/y OR no/n")
            if choice.lower() in ["y","yes"]:
                second_res = requests.put(
                    f"{URL}/user/passwords",
                    json = confid_app_data
                    )
                sec_res = second_res.json()
                if second_res.status_code == 503:
                    print("----------------------Password has been added-----------------------------")
                    return True
                else:
                    print(f"{sec_res["detail"]}")
            else:
                return False
        else:
            print(f"{res["detail"]}")
            return False
    
    def update_password(self):
        application_name = input("Enter the Application Name to be UPDATED : ")
        app_password = input("Enter the NEW Password for the application :")

        confid_app_data = EncryptDecryptService.encrypt_app_password(
            self.master_password,
            self.KEK_salt,
            app_password
        )
        confid_app_data["userid"] = self.user_id
        confid_app_data["application_name"] = application_name

        response = requests.put(
            f"{URL}/user/passwords",
            json=confid_app_data
            )
        res = response.json()
        if response.status_code == 200:
            print(f"{res["detail"]}")
            return True
        else:
            print(f"{res["detail"]}")
            return False
    
    def delete_password(self):
        application_name = input("Enter the Application Name to be DELETED : ")
        delete_app_data = {
            "userid" : self.user_id,
            "application_name" : application_name
        }

        response = requests.delete(
            f"{URL}/user/passwords",
            json = delete_app_data
        )
        res = response.json()
        if response.status_code == 200:
            print(f"{res["detail"]}")
            return True
        else:
            print(f"{res["detail"]}")
            return False




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
    