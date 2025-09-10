from models.user import UserCreate , UserLogin
from data_access.user_repository import UserRepository
from data_access.exceptions import DatabaseOperationError, DatabaseIntegrityError
from fastapi import HTTPException


import bcrypt , base64


class PasswordService:

    @staticmethod
    def salt_generation() -> bytes:
        return bcrypt.gensalt()

    @staticmethod
    def hash_password(plain_password: str, binary_salt: bytes) -> dict:
        binary_password = plain_password.encode("utf-8")
        binary_key = bcrypt.kdf(
            password=binary_password,
            salt=binary_salt,
            desired_key_bytes=32,
            rounds=100
        )
        base64_key_bytes = base64.b64encode(binary_key) # converts normal binary data into base64 encoded binary data
        base64_key_string = base64_key_bytes.decode("utf-8")

        return { 
            "key" : base64_key_string, 
            # "salt" = raw binary data -> base64 encoded binary -> utf-8 decoded string
            "salt" : (base64.b64encode(binary_salt)).decode("utf-8") 
        }

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str, salt: str):
        b64_binary_salt = salt.encode("utf-8")
        raw_binary_salt = base64.b64decode(b64_binary_salt)
        new_hashed_password = PasswordService.hash_password(plain_password,raw_binary_salt)
        if new_hashed_password["key"] == hashed_password:
            return True
        return False

class AuthService:
    def __init__(self):
        self.user_repo = UserRepository()
        self.pwd_service = PasswordService()

    def register_user(self, user_data: UserCreate):
        # Check if the EMAIL already exists
        if self.user_repo.user_exists(user_data.email) == True :
            print("Email is already registered")
            raise HTTPException(
                status_code = 400, 
                detail = "Email is already registered"
                )
        
        # Convert the master_password into hash with salt
        password_and_salt = self.pwd_service.hash_password(
            user_data.master_password,
            self.pwd_service.salt_generation()
            )

        data = {
            "email" : user_data.email,
            "hashed_password" : password_and_salt["key"],
            "salt" : password_and_salt["salt"]
        }
        # Send the data to store it in db
        if self.user_repo.create_user(data):
            return "User registered successfully"
        else:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable"
            )

    def authenticate_user(self, login_data: UserLogin):
        try:
            # Retrieve the user details if the user's email exists
            user = self.user_repo.get_user_by_email(login_data.email)
            if user == None:
                raise HTTPException(
                    status_code = 401, 
                    detail = "Register First"
                )
            # b64_binary_salt = user["salt"].encode("utf-8")
            # raw_binary_salt = base64.b64decode(b64_binary_salt)

            # Verify the current password for the given email id
            if self.pwd_service.verify_password( login_data.master_password, user["hashed_password"], user["salt"]):
                return {
                    "userid"  : user["userid"],
                    "detail" : "User is successfully authenticated"
                }
            else:
                raise HTTPException(
                    status_code = 501, 
                    detail = "Invalid email or password"
                )
        except DatabaseOperationError as e:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable"
            )
        except DatabaseIntegrityError as e:
            # This is a serious issue that needs attention
            raise HTTPException(
                status_code = 500,
                detail = "Internal server error"
            )


