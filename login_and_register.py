from db_connection import get_database_connection
from hash_and_enc import hash_generation   
import base64 , uuid , bcrypt

def register():
    username = input("Enter the Username : ")
    email    = input("Enter the email : ") 
    password = input("Enter the Master Password : ")

    # check if the email already exists, if yes exit the program

    conn = get_database_connection()
    curr = conn.cursor()
    
    check_query = """
    SELECT username , email FROM Credentials WHERE username=%s OR email=%s;
    """
    curr.execute(check_query,(username,email))
    rows = curr.fetchall() # rows will be in list of tuples
    # print(f'Matched Data - {rows}')
    for row in rows:
        if(row[0] == username):
            print("----------------------")
            print("The username is taken.")
            print("----------------------")
            register()
            return 1
        elif(row[1] == email):
            print("----------------------")
            print("This email is already registered.")
            print("----------------------")
            register()
            return 1
    if(len(rows) >= 1):   
        print(f"Either your USERNAME is Taken nor your EMAIL is already registered.")
    else:
        print(f"CONTINUE")

    table_query = """
    CREATE TABLE IF NOT EXISTS Credentials (
        userid varchar(255 ),
        username varchar(255),
        email varchar(255),
        password varchar(255),
        salt varchar(255)
    );
    """
    curr.execute(table_query)
    conn.commit()

    userid = str(uuid.uuid4())
    print(f"user-id - {userid}")

    binary_salt = bcrypt.gensalt()
    hash_data = hash_generation(password,binary_salt)
    print(f" Key - {hash_data["key"]}")
    print(f" Salt - {hash_data["salt"] }")

    insert_query = """
    INSERT INTO Credentials (userid, username, email, password, salt) 
    VALUES (%s, %s, %s, %s, %s);
    """
    curr.execute(insert_query,(userid, username, email, hash_data["key"], hash_data["salt"]))
    conn.commit()

    curr.close()
    conn.close()

    return 1

def login():
    email    = input("Enter the email : ") 
    password = input("Enter the Master Password : ")

    # open a db connection to retrive the salt
    conn = get_database_connection()
    curr = conn.cursor()
    retrival_query = """
    SELECT userid, username, salt, password FROM Credentials WHERE email=%s;
    """
    curr.execute(retrival_query,(email,)) # execute() expects a tuple for parameter substitution. Expected Format: curr.execute(query, (value,)) (a tuple with a comma!)
    rows = curr.fetchall() # its a tuple

    if(len(rows) == 0):
        print("----------------------")
        print("Please Register first.")
        print("----------------------")
        curr.close()
        conn.close()
        return 0
    elif(len(rows) == 1):
        row = rows[0]
        print(f"data - {row}")
        # Retrieved salt and password the DB 
        userid   = row[0] # int type
        username = row[1]
        salt     = row[2] 
        password_hash = row[3]
        #   print(type(id))
        binary_salt = base64.b64decode((salt.encode("utf-8")))
        hash_data = hash_generation(password,binary_salt)
        print(f"Hash Data - {hash_data["key"]}")
        if( password_hash ==  hash_data["key"]):
            print("You got LOGGED IN")
            curr.close()
            conn.close()
            return {"userid" : userid, "username" : username , "password_hash" : password_hash}
        else:
            print("Invalid Credentials")
            curr.close()
            conn.close()
            return 0
    else:
        print("----------------------")
        print("DUPLICATES entries detected.")
        print("----------------------")
        return 0