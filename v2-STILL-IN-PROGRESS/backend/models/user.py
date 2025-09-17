from pydantic import BaseModel , field_validator

# BaseModel is the fundamental building block of Pydantic. It's a class that provides:
# Data validation - Ensures data conforms to specified types and constraints
# Data serialization - Converts between Python objects and JSON/other formats
# Data parsing - Transforms raw input data into validated Python objects
# Schema generation - Creates JSON Schema documentation automatically

class UserCreate(BaseModel):
    email: str
    hashed_master_password: str
    KEK_salt: str

    @field_validator("email")
    def email_to_lower(cls, value: str) -> str:
        return value.lower()

class UserCreateInStorage(BaseModel):
    email: str
    password_hash: str
    salt: str

class UserLogin(BaseModel):
    email: str
    master_password: str

    @field_validator("email")
    def email_to_lower(cls, value: str) -> str:
        return value.lower()

# STILL NEED TO USE
# class UserResponse(UserCreate):
#     id: str
#     timestamp: datetime

class UserId(BaseModel):
    userid: str

class UserAppData(BaseModel):
    entryid: str
    userid: str
    application_name: str
    salt: str
    app_password: str
    iv: str
    auth_tag: str

    


