#include <iostream>
#include <cstdlib>

#include "encrypt.hpp"

#define SERVER "192.168.56.101"
#define PORT 12345

int main(void) {
    encrypt * e = new encrypt(ENCRYPT_CLIENT);
    e->loadCertificates("../certs/cert.pem", "../certs/key.pem");
    if (!e->openConnection(SERVER, PORT) ) {
        std::cout << "Connection Failed\n";
        return 1;
    }
    e->nonEncryptClient();
    return 0;
}
