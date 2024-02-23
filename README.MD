# Minimal openid setup
No special librarires. Generation and validation of jwt with openid flavor using minimal amount of properties.

# Example certificate
Example certificate and keys created in `keys` folder with:  
`openssl req -newkey rsa:2048 -nodes -keyout private_key.pem -x509 -days 365 -out certificate.pem`  
`openssl x509 -pubkey -noout -in certificate.pem > public_key.pem`  

