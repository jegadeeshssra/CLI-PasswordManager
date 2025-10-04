# Code to access data
import psycopg2 , os
from models.user import UserCreateInStorage , ConfidAppData
from db_ops.db_connection import DatabaseConnection
from .exceptions import DatabaseOperationError, DatabaseIntegrityError

import uuid

CREDS_TABLE_NAME = 'credentials'
DATASTORE_TABLE_NAME = 'DATASTORE'

class UserRepository:
    def __init__(self):
        self.db = DatabaseConnection()
    
    def create_user(self, user_data: UserCreateInStorage) -> bool:
        userid = str(uuid.uuid4())
        try:
            create_user_query = f"""
            INSERT INTO {CREDS_TABLE_NAME} (userid, email, master_password, salt) 
            VALUES (%s  , %s, %s, %s);
            """
            self.db.cursor.execute(create_user_query,(userid,user_data["email"], user_data["hashed_password"], user_data["salt"]))
            self.db.connection.commit()
            return True

        except psycopg2.Error as e:
            self.db.connection.rollback()
            print(f"Database error: {e}")
            return False

    def modify_user(self, modified_user_data: UserModifyInStorage) -> bool:
        try:
            modify_user_query = f"""
            UPDATE{CREDS_TABLE_NAME}
            SET master_password = %s , salt = %s
            WHERE userid = %s;
            """
            self.db.cursor.execute(modify_user_query,(modified_user_data["hashed_password"], modified_user_data["salt"], modified_user_data["userid"]))
            self.db.connection.commit()
            return True

        except psycopg2.Error as e:
            self.db.connection.rollback()
            print(f"Database error: {e}")
            return False

    def get_user_by_email(self, email: str) -> dict:
        try:
            retrival_query = f"""
            SELECT userid, salt, master_password FROM {CREDS_TABLE_NAME} WHERE email=%s;
            """
            self.db.cursor.execute(retrival_query,(email,)) # execute() expects a tuple for parameter substitution. Expected Format: curr.execute(query, (value,)) (a tuple with a comma!)
            rows = self.db.cursor.fetchall() # its a tuple
            if len(rows) == 1:  
                row = rows[0]
                userid = row[0]
                salt = row[1]
                hashed_password = row[2]
                return {
                    "userid" : userid,
                    "salt"  : salt,
                    "hashed_password" : hashed_password
                }

            elif len(rows) == 0:
                return None
            else:
                # Raise specific exception for database integrity issue
                raise DatabaseIntegrityError(
                    f"Database integrity violation: {len(rows)} users found with email: {email}"
                )       
        except psycopg2.Error as e:
            # Log the actual error but raise a generic exception
            print(f"DatabaseOperational error in get_user_by_email: {e}")
            raise DatabaseOperationError(
                "Failed to retrieve user data"
                ) from e    

    def user_exists(self, email: str) -> bool:
        check_query = f"""
        SELECT * FROM {CREDS_TABLE_NAME} WHERE email=%s;
        """
        self.db.cursor.execute(check_query,(email,))
        rows = self.db.cursor.fetchall()
        #print("rows - ",rows)
        if len(rows) == 0:
            return False
        else:
            return True


class CrudRepository:
    def __init__(self):
        self.db = DatabaseConnection()
        #print("CrudRepository Initialized")

    def get_all_passwords(self, userid: str) -> [[]]:
        try:
            retrival_query = f"""
            SELECT * FROM {DATASTORE_TABLE_NAME} WHERE userid=%s;
            """
            self.db.cursor.execute(retrival_query,(userid,)) # execute() expects a tuple for parameter substitution. Expected Format: curr.execute(query, (value,)) (a tuple with a comma!)
            rows = self.db.cursor.fetchall() # its a tuple
            if len(rows) > 0:  
                return rows
            elif len(rows) == 0:
                return None
        except psycopg2.Error as e:
            # Log the actual error but raise a generic exception
            print(f"DatabaseOperational error in get_all_passwords: {e}")
            raise DatabaseOperationError(
                "Failed to retrieve user passwords"
                ) from e 
    
    def application_exists(self, userid: str, application_name: str) -> list:
        try:
            check_query = f"""
            SELECT * FROM {DATASTORE_TABLE_NAME} WHERE userid=%s AND application_name=%s;
            """
            self.db.cursor.execute(check_query,(userid,application_name))
            rows = self.db.cursor.fetchall()
            #print("rows - ",rows)
            if len(rows) == 1:
                return rows[0]
            elif len(rows) == 0:
                return False
            else:
                # Raise specific exception for database integrity issue
                raise DatabaseIntegrityError(
                    f"Database integrity violation: {len(rows)} entries were found for this user with the same application name: {application_name}"
                )       
        except psycopg2.Error as e:
            self.db.connection.rollback()
            # Log the actual error but raise a generic exception
            print(f"DatabaseOperational error in get_user_by_email: {e}")
            raise DatabaseOperationError(
                "Failed to retrieve user data"
                ) from e    

    def add_password(self, app_data: ConfidAppData):
        try:
            entryid = str(uuid.uuid4())
            add_query = f"""
            INSERT INTO {DATASTORE_TABLE_NAME}( entryid, userid, application_name, salt, app_password, iv, auth_tag)
            values (%s,%s,%s,%s,%s,%s,%s)
            """
            self.db.cursor.execute(add_query,( 
                    entryid, 
                    app_data["userid"], 
                    app_data["application_name"], 
                    app_data["salt"],
                    app_data["app_password"], 
                    app_data["nonce"], 
                    app_data["auth_tag"]
                    ))
            self.db.connection.commit()
            return True

        except psycopg2.Error as e:
            self.db.connection.rollback()
            print(f"Database error: {e}")
            raise DatabaseOperationError(
                "Unable to add password"
                ) from e   
    
    def update_password(self, app_data: ConfidAppData):
        try:
            update_query = f"""
            UPDATE {DATASTORE_TABLE_NAME}
            SET salt = %s , app_password = %s , iv = %s , auth_tag = %s
            WHERE userid = %s AND application_name = %s;
            """
            self.db.cursor.execute(update_query,(
                app_data["salt"],
                app_data["app_password"], 
                app_data["nonce"], 
                app_data["auth_tag"],
                app_data["userid"],
                app_data["application_name"]
            ))
            self.db.connection.commit()
            return True

        except psycopg2.Error as e:
            self.db.connection.rollback()
            print(f"Database error: {e}")
            raise DatabaseOperationError(
                "Unable to update the password"
                ) from e   

    def delete_password(self, userid: str, app_name: str):
        try:
            delete_query = f"""
            DELETE FROM {DATASTORE_TABLE_NAME}
            WHERE userid = %s AND application_name = %s;
            """
            self.db.cursor.execute(delete_query,(
                userid,
                app_name
            ))
            self.db.connection.commit()
            return True
            
        except psycopg2.Error as e:
            self.db.connection.rollback()
            print(f"Database error: {e}")
            raise DatabaseOperationError(
                "Unable to delete the password"
                ) from e   