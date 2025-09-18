from models.user import UserCreate , UserLogin
from data_access.user_repository import UserRepository
from data_access.exceptions import DatabaseOperationError, DatabaseIntegrityError
from fastapi import HTTPException


import bcrypt , base64

class AuthService:
    def __init__(self):
        self.user_repo = UserRepository()

    def register_user(self, user_data: UserCreate):
        # Check if the EMAIL already exists
        if self.user_repo.user_exists(user_data.email) == True :
            print("Email is already registered")
            raise HTTPException(
                status_code = 400, 
                detail = "Email is already registered"
                )

        data = {
            "email" : user_data.email,
            "hashed_password" : user_data.hashed_master_password,
            "salt" : user_data.KEK_salt
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

            return {
                "userid" : user["userid"],
                "hashed_master_password" : user["hashed_password"],
                "KEK_salt" : user["salt"]
            }
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


