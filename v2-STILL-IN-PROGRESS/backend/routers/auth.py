from models.user import UserCreate , UserLogin , UserModify
from services.auth_service import AuthService
from fastapi import APIRouter

router = APIRouter(tags=["Authentication"])

# actual_path - /auth/register
@router.post("/register")
def register(user_data: UserCreate):
    auth_service = AuthService()
    # FastAPI automatically validates user_data against UserCreate schema
    return auth_service.register_user(user_data)  # Delegate to service layer

# actual_path - /auth/login
@router.post("/login")
def login(login_data: UserLogin):
    auth_service = AuthService()
    return auth_service.authenticate_user(login_data)

# actual_path - /auth/forgotPassword
@router.post("/forgotPassword")
def forgot_password(modified_user_data: UserModify):
    auth_service = AuthService()
    return auth_service.modify_user(modified_user_data)