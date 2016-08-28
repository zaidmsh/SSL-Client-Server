#include <iostream>
#include <cstdlib>

#include "encrypt.hpp"

#define SERVER "192.168.56.101"
#define PORT 12345

int main(void) {
    encrypt * e = new encrypt(ENCRYPT_SERVER);
    e->loadCertificates("../certs/cert.pem", "../certs/key.pem");
    if (!e->openConnection(SERVER, PORT)) {
        std::cout << "Connection failed\n";
        return 1;
    }

    while (1) {
        e->nonEncryptServer();
    }
    return 0;
}
