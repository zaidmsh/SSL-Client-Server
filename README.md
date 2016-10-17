# SSL client/server application to exchange data

## Create server certificate
Before we use openssl we need to create a certificate for the server. In order to do that we have to use CA to sign the server's certificate.
so if we don't have a CA then we have to create one.

### Create CA
There are two steps to create the CA:
1. Create root certificate
2. Create CA using the root certificate

#### Create root Certificate

##### Create root_key & root_request
    `openssl req -newkey rsa:2048 -keyout root_key.pem -out root_request.pem`

##### Create root_certificate
    `openssl x509 -req -in root_request.pem -signkey root_key.pem -out root_certificate.pem`

##### Combine root_certificate & root_key
    `cat root_certificate.pem root_key.pem > root.pem`

#### Create CA using the root certificate

##### Generate CA's private key & certificate request
    `openssl req -newkey rsa:2048 -keyout CA_key.pem -out CA_request.pem`

##### Create the CA
    `openssl x509 -req -in CA_request.pem -CA root.pem -CAkey root.pem -CAcreateserial -out CAcert.pem`

##### Combine CA's cert, key and root_certificate
    `cat CAcert.pem CA_key.pem root_certificate.pem > CA.pem`


### Create the server's certificate

#### Generate server's key and request
    `openssl genrsa 2048 > server_key.pem`
    `openssl req -new -key server_key.pem -out server_request.pem`

#### Process the server's certificate with CA
    `openssl x509 -req -in server_request.pem -CA CA.pem -CAcreateserial -CAkey CA.pem -out server_certificate.pem`

#### Combine
    `cat server_certificate.pem server_key.pem CAcert.pem root_certificate.pem > server.pem`
