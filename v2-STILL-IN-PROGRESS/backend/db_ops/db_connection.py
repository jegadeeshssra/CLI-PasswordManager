# This class implements a singleton pattern which basically just allow the program to create a single instance of this class
import psycopg2 , os
from dotenv import load_dotenv
load_dotenv()

class DatabaseConnection:   
    _instance = None

    # This __new__ class runs before the __init__ function and by writing this , we can control the way an object is intialize
    def __new__(cls):           
        if cls._instance is None:
            cls._instance = super().__new__(cls)    # this calls the base class's new function to create an instance of this class  
            cls._instance._intialize_connection()
            return cls._instance
        return cls._instance                # Needs to return the _instance variable for other requests except the first one
        
    def _intialize_connection(self):
        try:
            self.connection =   psycopg2.connect(
                database = os.getenv("DB_NAME"),
                user = os.getenv("DB_USER"),
                password = os.getenv("DB_PASSWORD"),
                host = os.getenv("DB_HOST"),
                port = os.getenv("DB_PORT")
            )
            print("DB Connection ESTABLISHED")
            self.cursor = self.connection.cursor()
            return self.connection
        except psycopg2.Error as e:
            print(f"Connection FAILED : {e}")
            return None

# print("---------------------------------------------------------")
# print("---------------------------------------------------------")
# obj = DatabaseConnection()
# print("--------------------------------------------")
# print(obj)
# print("--------------------------------------------")
# print(obj.connection)
# print("--------------------------------------------")
# print(obj.cursor)
# print("---------------------------------------------------------")
# print("---------------------------------------------------------")
