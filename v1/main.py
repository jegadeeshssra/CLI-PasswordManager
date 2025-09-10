from db_connection import get_database_connection
from hash_and_enc import hash_generation , encrypt_AES_GCM , decrypt_AES_GCM , str_to_bytes, bytes_to_str ,str_to_rawBytes ,rawBytes_to_str
from login_and_register import login , register
import base64
import typer
import re , uuid , time , random
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
        login_data = login()
        if login_data != 0 :
            print(type(login_data))
            show_features(login_data)
            # Display menu for displaying passwords , updating them , adding them , deleting them
        else:
            print(type(login_data))
            login()
    elif(initial_option == 2):
        register()
        main()
    else:
        exit()
    return 1

def show_features(login_data : dict):
    userid   = str(login_data["userid"])
    username = login_data["username"]
    password_hash = login_data["password_hash"]         # hash of login-password
    

    while True:
        try:
            print(f"Welcome {username} \n 1 - SHOW Passwords\n 2 - ADD Password\n 3 - UPDATE Password\n 4 - DELETE Password\n 5 - EXIT")
            initial_option = int(input("Enter the Option : "))
            if( 0 < initial_option < 6 ):
                print(f"{initial_option}")
                break
            else:       
                raise ValueError("Choose the given options")
        except ValueError:
            print("------RETRY - Invalid Input-------")

    if(initial_option == 1):
        conn = get_database_connection()
        curr = conn.cursor()
        display_query = """
        SELECT application_name , salt , app_password , iv , auth_tag 
        FROM Datastore WHERE userid=%s;
        """
        curr.execute(display_query,(userid,)) # Single argument tuple not an STRING
        rows = curr.fetchall()  

        password_hash = str_to_bytes(password_hash)

        print("----------------------------------------------------------")
        for row in rows:
            print("ROW - ",row)
            app_name            = row[0]
            salt                = str_to_rawBytes(row[1])
            cipher_app_password = str_to_rawBytes(row[2])
            iv                  = str_to_rawBytes(row[3])
            auth_tag            = str_to_rawBytes(row[4])

            plain_app_password = decrypt_AES_GCM(password_hash,salt,cipher_app_password,iv,auth_tag)
            #print(type(plain_app_password)) #bytes
            print(f"\nApplication - {app_name}")
            print(f"password    - {bytes_to_str(plain_app_password)}\n")
        print("----------------------------------------------------------")
        
        # get all entries of the user in single query (Limit displays by page size)
        # decrypt all the passwords and display it
        # display nothing if there is no entries with a message

        curr.close()
        conn.close()

        show_features(login_data)

    elif(initial_option == 2):
        # print("here")
        conn = get_database_connection()
        curr = conn.cursor()
        table_query = """
        CREATE TABLE IF NOT EXISTS Datastore (
            entryid varchar(255),
            userid varchar(255),
            application_name varchar(255),
            salt varchar(64),
            app_password varchar(255),
            iv varchar(64),
            auth_tag varchar(64)
        );
        """
        curr.execute(table_query)
        conn.commit()

        app_name = input("Enter the Application Name (email, website, app) : ")
        app_password = input("Enter the password for the applciation :")

        encrypted_msg = encrypt_AES_GCM(str_to_bytes(app_password),str_to_bytes(password_hash))
        ( salt , ciphertext , IV , auth_tag ) = encrypted_msg
        # app_password  - application's password
        # password_hash - hash of login-password

        print("SALT - ")
        print(len(salt))
        print(type(salt))
        print("IV - ")
        print(len(IV))
        print(type(IV))

        # raw bytes -> base64 encoded bytes -> ASCII decoded string
        salt = (base64.b64encode(salt)).decode("ascii")
        ciphertext = (base64.b64encode(ciphertext)).decode("ascii")
        IV = (base64.b64encode(IV)).decode("ascii")
        auth_tag = (base64.b64encode(auth_tag)).decode("ascii")

        def custom_ids():
            timestamp = int(time.time() * 1000) # converts the current floatPoint time(s) into an ms of type integer
            random_part = random.randint(1000,9999)
            return f'{timestamp}{random_part}'

        entryid = custom_ids()
        print(entryid)

        add_query = """
        INSERT INTO Datastore( entryid, userid, application_name, salt, app_password, iv, auth_tag)
        values (%s,%s,%s,%s,%s,%s,%s)
        """
        curr.execute(add_query,( entryid, userid, app_name, salt, ciphertext, IV, auth_tag))
        conn.commit()

        print("Your password has been added.")

        #rows = curr.fetchall()

        # ask for entry name like email or application name or website name
        # enter the password
        # encrypt the password and store the password & its key in the DB (multiple options in future)

        curr.close()
        conn.close()

        show_features(login_data)

    elif(initial_option == 3):

        app_name = input("Enter the Application Name : ")
        new_password = input("Enter the NEW App Password : ")

        encrypted_msg = encrypt_AES_GCM(new_password.encode("ascii"),password_hash.encode("ascii"))
        (salt , ciphertext , iv , auth_tag) = encrypted_msg

        salt = base64.b64encode(salt).decode("ascii")
        ciphertext = base64.b64encode(ciphertext).decode("ascii")
        iv = base64.b64encode(iv).decode("ascii")
        auth_tag = base64.b64encode(auth_tag).decode("ascii")

        conn = get_database_connection()
        curr = conn.cursor()
        query = """
        UPDATE Datastore 
        SET salt = %s , app_password = %s , iv = %s , auth_tag = %s
        WHERE userid = %s AND application_name = %s;
        """
        curr.execute(query,(salt, ciphertext, iv, auth_tag, userid, app_name))
        conn.commit()

        # ask for which entry to update with password 
        # encrpyt the new password

        curr.close()
        conn.close()

        show_features(login_data)

    elif(initial_option == 4):
        
        app_name = input("Enter the Application Name To be DELETED : ")

        conn = get_database_connection()
        curr = conn.cursor()
        query = """
        DELETE FROM Datastore 
        WHERE userid = %s AND application_name = %s;
        """
        curr.execute(query,(userid,app_name))
        conn.commit()

        curr.close()
        conn.close()

        show_features(login_data)

    elif(initial_option == 5):
        main()


if __name__ == "__main__":
    app()
