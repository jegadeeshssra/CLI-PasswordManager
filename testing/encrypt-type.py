from db_connection import get_database_connection
from hash_and_enc import hash_generation , encrypt_AES_GCM , decrypt_AES_GCM
from login_and_register import login , register
import base64
import typer
import re , uuid , time , random


app_name = input("Enter the Application Name (email, website, app) : ")
app_password = input("Enter the password for the applciation :")
password_hash = "vfsv"

encrypted_msg = encrypt_AES_GCM(app_password.encode("utf-8"),password_hash.encode("utf-8"))
( salt , ciphertext , IV , auth_tag ) = encrypted_msg
# app_password  - application's password
# password_hash - hash of login-password


print("SALT - ")
print(salt)

print("IV - ")
print(len(IV))
print(type(IV))

salt = base64.b64encode(salt).decode("ascii")
print("salt - ",salt)
print(type(salt))