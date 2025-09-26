#from models.user
from data_access.user_repository import UserRepository , CrudRepository
from data_access.exceptions import DatabaseOperationError, DatabaseIntegrityError
from fastapi import HTTPException
from models.user import UserCreate , UserCreateInStorage , ConfidAppData , DeleteAppData , UserLogin
import bcrypt , base64

class CrudService:
    def __init__(self):
        self.crud_repo = CrudRepository()
        #self.encrypt_decrypt_service = EncryptDecryptService()

    def get_all_passwords(self, userid: str):
        try:
            #   print(userid)
            rows = self.crud_repo.get_all_passwords(userid)
            if rows == None:
                raise HTTPException(
                    status_code = 404,
                    detail = "Add Your First Password"
                )
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


    def add_password(self, data: ConfidAppData):
        try:
            app_data = data.model_dump()
            #print(app_data)
            if self.crud_repo.application_exists( app_data["userid"], app_data["application_name"]):
                raise HTTPException(
                    status_code = 400,
                    detail = "Application name is already used"
                )
            if self.crud_repo.add_password(app_data):
                return {
                    "userid" : app_data["userid"],
                    "detail" : "Password Added successfully"
                }

        except DatabaseOperationError as e:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable" 
            )
        except DatabaseIntegrityError as e:
            raise HTTPException(
                status_code = 409,
                detail = "Too many entries for the same application name"
            )

    def update_password(self, data: ConfidAppData):
        try:
            app_data = data.model_dump()
            if self.crud_repo.application_exists( app_data["userid"], app_data["application_name"]):
                if self.crud_repo.update_password(app_data):
                    return {
                        "userid" : app_data["userid"],
                        "detail" : "Password Updated successfully"
                    }
            else:
                    raise HTTPException(
                        status_code = 400,
                        detail = "Application name does not exists"
                    )
        except DatabaseOperationError as e:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable" 
            )

    def delete_password(self, data: DeleteAppData):
        try:
            app_data = data.model_dump()
            if self.crud_repo.application_exists( app_data["userid"], app_data["application_name"]):
                if self.crud_repo.delete_password( app_data["userid"], app_data["application_name"]):
                    return {
                        "userid" : app_data["userid"],
                        "detail" : "App Password deleted successfully"
                    }
            else:
                    raise HTTPException(
                        status_code = 400,
                        detail = "Application name is does not exists"
                    )
        except DatabaseOperationError as e:
            raise HTTPException(
                status_code = 503,
                detail = "Service temporarily unavailable" 
            )
