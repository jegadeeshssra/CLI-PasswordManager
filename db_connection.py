import psycopg2
from dotenv import load_dotenv

load_dotenv()

def get_database_connection():
    try:
        conn = psycopg2.connect(
            user = os.getenv("DB_USER"),
            password = os.getenv("DB_PASSWORD"),
            host = os.getenv("DB_HOST"),
            port = os.getenv("DB_PORT")
        )
        print("DB Connection ESTABLISHED")
        return conn
    except psycopg2.Error as e:
        print(f"Connection FAILED : {e}")
        return None


        