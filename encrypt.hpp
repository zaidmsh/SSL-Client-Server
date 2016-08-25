#ifndef ENCRYPT_H_
#define ENCRYPT_H_

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define ENCRYPT_SERVER 1
#define ENCRYPT_CLIENT 2
#define BUF_SIZE 1024

class encrypt {
    public:
        encrypt(int mode);
        encrypt();
        ~encrypt();
        bool loadCertificates(const char * CertFile, const char * KeyFile);
        bool openBioConnection(const char * hostname, int port);
        bool openConnection(const char * hostname, int port);
        bool client();
        bool clientBio();
        bool server();
        bool serverBio();
        bool read(char * buf, std::size_t len);
        bool write(const char * buf, std::size_t len);
    private:
        int sock;
        int mode;
        BIO * in_bio, * out_bio;
        SSL_CTX * ctx;
        SSL * ssl;
        void serve(SSL * ssl);
};
#endif
