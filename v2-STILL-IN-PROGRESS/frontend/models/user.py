from pydantic import BaseModel, EmailStr, ValidationError

class UserData(BaseModel):
    email: EmailStr
    hashed_master_password: str
    KEK_salt : str

class UserLoginData(BaseModel):
    email: EmailStr

class UserPasswordData(BaseModel):
    application_name: str
    app_password: str