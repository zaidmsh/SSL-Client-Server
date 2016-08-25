#include <iostream>

#include "encrypt.hpp"

#define SERVER "192.168.56.101"
#define PORT 12345

int main() {
    encrypt * e = new encrypt(ENCRYPT_CLIENT);
    e->loadCertificates("../certs/cert.pem", "../certs/key.pem");
#if 1
    if (!e->openConnection(SERVER, PORT) ) {
        std::cout << "Connection Failed\n";
        return 1;
    }
    e->client();
#else
    if (!e->openBioClient(SERVER, PORT) ) {
        std::cout << "Connection Failed\n";
        return 1;
    }
    e->clientBio();
#endif
    return 0;
}
