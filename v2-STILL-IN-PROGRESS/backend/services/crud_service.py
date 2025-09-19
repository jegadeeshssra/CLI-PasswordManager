#from models.user
from data_access.user_repository import UserRepository
from data_access.exceptions import DatabaseOperationError, DatabaseIntegrityError
from fastapi import HTTPException
import bcrypt , base64

class CrudService:
    def __init__(self):
        self.crud_repo = CrudRepository()
        #self.encrypt_decrypt_service = EncryptDecryptService()

    def get_all_passwords(self, userid: str):
        try:
            rows = self.crud_repo.get_all_passwords(userid)
            if rows == None:
                return {
                        "userid"  : userid,
                        "detail" : "Add your first password"
                    }
            return {
                "userid" : userid,
                "detail": "Data sent",
                "data": rows 
            }
        except DatabaseOperationError as e:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable"
            )


    def add_password(self, app_data: ConfidAppData):
        try:
            if "replace" not in app_data:
                if self.crud_repo.application_exists( app_data["userid"], app_dir["application_name"]):
                    raise HTTPException(
                        status_code = 400,
                        detail = "Application name is already used"
                    )
            if self.crud_repo.add_password(app_data):
                return {
                    "userid" : app_data["user_id"]
                    "detail" : "Password Added successfully"
                }

        except DatabaseOperationError as e:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable" 
            )

    def update_password(self):

    def delete_password(self):
