
Argon2's Security Design
- argon2Hasher.verify() uses constant-time comparison
- Exceptions are thrown instead of returning False to prevent timing leaks
- Same execution time whether password is correct or not
- Prevents attackers from measuring response times to guess valid passwords