----------------
Design Decisions
----------------


Security Decisions
------------------

- Every hashing , encryption and decryption is being done on the client side for better security and to implement Zero-Knowledge Security.
- No plaintext passwords are being sent to or stored on the backend.
- No encryption/decryption keys are stored on the Backend

Registration
- During Registration , the master_password is used to generate KEK(Argon2) with random salt and using the KEK , DEK(randomly generated) is encrypted and then the encrypted_DEK is stored on the client side(-------HERE--------).
- The purpose of using random salt with master password is to regenrate the same KEK, if we combine both master_password and random salt for the argon2 hashing function, it generated the same hash.

Login Authentication
- argon2 is used for hashing the master_password(without the salt) on the client side and the hashed password is then sent to the server side for storage.
- Here the purpose of not using a random salt for argon2 hashing is to get unique hashes for the same master_password.
- During the login, the login_password is verified by verify() func with the currently  entered master password and previously stored hashed_master_password.

App Password Encryption
- During Registration , the master_password is used to generate KEK with random salt(Argon2 - as we are using salt this time, the final hash can be regenerated using the same master_password and the random salt) and using the KEK , DEK(randomly generated) is encrypted and then the encrypted_DEK is stored on the client side(-------HERE--------).
- During the Login, master_password is used to create the KEK and when inturn is used to decrypt the Encrypted_DEK.
- Now , for every new password added, it will be encrypted using the decrypted_DEK on the client-side and then it will be sent to the backend for storing it in DB.

App Password Decryption
- During the Login, master_password is used to create the KEK and when inturn is used to decrypt the Encrypted_DEK.
- For showing the app passwords to the client after login, every encrypted app passwords of that particular user are being retrieved from the DB to the client-side and gets decrypted one by one(not all at once) as the user selects using the decrypted DEK.

Recovery Key
- During registration itself , a random key as recovery key will be generated and will be used to encrypt the DEK. So, that if the user forgots his/her master_password, DEK key can be retrieved using the recovery key
- Both Recovery Key and the encrypted DEK will be stored on the Local or cloud on user's perference.

Re-encryption of App Password with New Password
- If the user forgots his/her master_password, recovery key will be used to decrypt the encrypted_DEK.
- Now, a new KEK will be generated with(new master_password + new random_salt) and using the new KEK, DEK will be encrypted and stored on the local system


Forgot password
- Use the uploaded recovery key 
- decrypt the DEK
- Get the new password
- generate a new salt KEK
- DELETE the old Login record from the DB(includes hash,KEK_salt,kdf_params)
- Using the new master_password, generate KEK and encrypt the DEK and store it.

