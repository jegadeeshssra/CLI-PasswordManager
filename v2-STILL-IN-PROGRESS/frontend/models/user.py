from pydantic import BaseModel, EmailStr, ValidationError

class UserData(BaseModel):
    email: EmailStr
    hashed_master_password: str
    KEK_salt : str

class ModifiedUserData(BaseModel):
    userid: str
    email: EmailStr
    new_hashed_master_password: str
    new_KEK_salt : str


class UserLoginData(BaseModel):
    email: EmailStr

class UserPasswordData(BaseModel):
    application_name: str
    app_password: str

class DeleteAppData(BaseModel):
    userid: str
    application_name: str    