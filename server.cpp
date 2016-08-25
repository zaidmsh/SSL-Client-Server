#include <iostream>

#include "encrypt.hpp"

#define SERVER "192.168.56.101"
#define PORT 12345

int main() {
    encrypt * e = new encrypt(ENCRYPT_SERVER);
    e->loadCertificates("../certs/cert.pem", "../certs/key.pem");
#if 1 
    if (!e->openConnection(SERVER, PORT)) {
        std::cout << "Connection failed\n";
        return 1;
    }
    e->server();
#else
    if (!e->openBioServer(SERVER, PORT)) {
        std::cout << "Connection failed\n";
        return 1;
    }
    e->serverBio();
#endif
    return 0;
}
