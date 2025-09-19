from models.user import UserId
from services.crud_service import CrudService
from fastapi import APIRouter

router = APIRouter(tags=["CrudService"])

# actual_path - /user/passwords
@router.get("/passwords")
def get_all_passwords(user_id: UserId):
    crud_service = CrudService()
    # FastAPI automatically validates user_data against UserCreate schema
    return crud_service.get_all_passwords(user_id)  # Delegate to service layer

@router.post("/passwords")
def add_password(confid_app_data: ConfidAppData):
    crud_service = CrudService()
    return crud_service.add_password(confid_app_data)

# actual_path - /auth/login
# @router.post("/login")
# def login(login_data: UserLogin):
#     auth_service = AuthService()
#     return auth_service.authenticate_user(login_data)