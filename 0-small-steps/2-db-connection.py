import psycopg2

host = "localhost"
user = "postgres"
password = "postgres"
port = 5432

def get_connection():
    try:
        # The function get_connection attempts to establish a connection to the PostgreSQL database using the psycopg2.connect method.
        return psycopg2.connect(            
            #database="postgres",
            user=user,
            password=password,
            host=host,
            port=port
        )
    except:
        return False
conn = get_connection()

if conn :
    print("CONNECTION ESTABLISHED")
    print(conn)
else:
    print("Connection Unsuccessful")

# The cursor is an abstraction that allows you to execute SQL commands and fetch results.
curr = conn.cursor()

# Connection Object:
# - Represents the session with the database.
# - Handles transaction management (commit, rollback).
# - Creates the cursor object for executing queries.
# Cursor Object:
# - Executes SQL commands and fetches query results.
# - Operates independently within the context of the connection.

curr.execute("DROP TABLE credentials;")
conn.commit()

# 'execute' method sends your SQL commands to the database, allowing you to manipulate data and structure within the database.
curr.execute("CREATE TABLE credentials (UserID int,Username varchar(255),Email varchar(255),Password varchar(255));")
# Commits finalize the transaction, ensuring your changes are saved to the database.
# Without a commit, changes remain in a temporary state and may be rolled back.
conn.commit()

curr.execute("INSERT INTO credentials (UserID, Username, Email, Password) VALUES (1, 'Smith', 'smith@gmail.com', 'Metropolis'),(2,'jaggu','j@gmail.com','vfavefavqa');")
conn.commit()

curr.execute("SELECT * FROM credentials;")
# The SELECT statement is a read-only operation. It retrieves data from the database but does not modify it. Here’s why commit() is unnecessary for SELECT
rows = curr.fetchall()  # Retrieves all rows returned by the query as a list of tuples.
print("Data in Credentials table:")
for row in rows:
    print(row)

# Close the cursor and connection
curr.close()    # Closes the cursor, releasing resources it holds.
conn.close()
print("PostgreSQL connection closed.")


