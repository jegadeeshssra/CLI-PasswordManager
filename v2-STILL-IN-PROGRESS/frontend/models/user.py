from pydantic import BaseModel, EmailStr, ValidationError

class UserData(BaseModel):
    email: EmailStr
    master_password: str

class UserPasswordData(BaseModel):
    application_name: str
    app_password: str