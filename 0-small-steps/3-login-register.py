import psycopg2
import bcrypt
import base64
import typer
app = typer.Typer()

@app.command()
def main():
    while True:
        try:
            print("Welcome to the Password Store \n 1 - Login\n 2 - Register\n 3 - EXIT")
            initial_option = int(input("Enter the Option : "))
            if( 0 < initial_option < 4 ):
                break
            else:
                raise ValueError("Choose the given options")
        except ValueError:
            print("------RETRY - Invalid Input-------")

    if(initial_option == 1):
        if Login() :
            show_features()
            # Display menu for displaying passwords , updating them , adding them , deleting them
    elif(initial_option == 2):
        Register()
    else:
        exit()
    return 1

def get_database_connection():
    try:
        conn = psycopg2.connect(
            user="postgres",
            password="postgres",
            host="localhost",
            port=5432
        )
        print("DB CONECTION ESTABLISHED")
        return conn
    except psycopg2.Error as e:
        print(f"Connection Failed : {e}")
        return None

def hash_generation( password: str, binary_salt: str ):
    # Some functions (like hashing, encryption, or KDFs) specifically require binary data because they operate at 
    #   the byte level.
    binary_password = password.encode('utf-8') # String to binary data
    binary_key = bcrypt.kdf(    # Produce the key in binary format 
        password=binary_password,
        salt=binary_salt,
        desired_key_bytes=32,
        rounds=100
    )
    #print(f"Binary Data - {binary_password}")   
    # print(f"Binary Data - {type(binary_password)}")   
    #print(f"Salt - {binary_salt}")
    # print(f"Salt - {type(binary_salt)}")
    #print(f"Derived Key - {binary_key}")
    # print(f"Derived Key - {type(binary_key)}")  

    base64_key_bytes = base64.b64encode(binary_key) # converts normal binary data into base64 encoded binary data
    base64_key_string = base64_key_bytes.decode("utf-8")
    #print(f"Base64 key byte string - {base64_key_bytes}")
    # print(f"Base64 key byte string - {type(base64_key_bytes)}")
    print(f"Base64 encoded Key String - {base64_key_string}")
    # print(f"Base64 encoded Key String - {type(base64_key_string)}")
                                            # raw binary data -> base64 encoded binary -> utf-8 decoded string
    return { "key" : base64_key_string, "salt" : (base64.b64encode(binary_salt)).decode("utf-8") }

def Register():
    username = input("Enter the Username : ")
    email    = input("Enter the email : ") 
    password = input("Enter the Master Password : ")

    # check if the email already exists, if yes exit the program

    conn = get_database_connection()
    curr = conn.cursor()
    table_query = """
    CREATE TABLE IF NOT EXISTS Credentials (
        userid int,
        username varchar(255        ),
        email varchar(255),
        password varchar(255),
        salt varchar(255)
    );
    """
    curr.execute(table_query)
    conn.commit()

    binary_salt = bcrypt.gensalt()
    hash_data = hash_generation(password,binary_salt)
    print(f" Key - {hash_data["key"]}")
    print(f" Salt - {hash_data["salt"] }")

    # When executing the query, the database driver replaces %s with actual values, ensuring proper escaping and 
    # preventing SQL injection.
    insert_query = """
    INSERT INTO Credentials (userid, username, email, password, salt) 
    VALUES (%s, %s, %s, %s, %s);
    """
    curr.execute(insert_query,(1, username, email, hash_data["key"], hash_data["salt"]))
    conn.commit()

    curr.close()
    conn.close()

    return 1

def Login():
    email    = input("Enter the email : ") 
    password = input("Enter the Master Password : ")

    # open a db connection to retrive the salt
    conn = get_database_connection()
    curr = conn.cursor()

    retrival_query = """
    SELECT salt , password FROM Credentials WHERE email=%s;
    """
    curr.execute(retrival_query,(email,)) # execute() expects a tuple for parameter substitution. Expected Format: curr.execute(query, (value,)) (a tuple with a comma!)
    rows = curr.fetchall() # its a tuple
    # print(f"{type(rows)}")        # Rows is a LIST of TUPLES
    if(len(rows) == 0):
        print("----------------------")
        print("Please Register first.")
        print("----------------------")
        curr.close()
        conn.close()
        return main()
        
    for row in rows:
        print(f"data - {row}")
        # print(type(row))          # TUPLES
    
    # Retrieved salt and password the DB 
    salt = row[0]
    key =  row[1]

    # salt string -> base64 binary salt -> raw binary salt
    binary_salt = base64.b64decode((salt.encode("utf-8")))
    hash_data = hash_generation(password,binary_salt)
    if( key ==  hash_data["key"]):
        print("You got LOGGED IN")
        curr.close()
        conn.close()
        return 1
    else:
        print("Invalid Credentials")
        curr.close()
        conn.close()
        return 0




if __name__ == "__main__":
    app()
