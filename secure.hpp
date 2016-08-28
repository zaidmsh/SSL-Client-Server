#ifndef SECURE_H_
#define SECURE_H_

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define SECURE_SERVER 1
#define SECURE_CLIENT 2
#define BUF_SIZE 1024

class secure {
    public:
        secure(int mode);
        ~secure();
        bool loadCertificates(const char * CertFile, const char * KeyFile);
        bool openConnection(const char * hostname, int port);
        bool secureClient();
        bool nonSecureClient();
        bool secureServer();
        bool nonSecureServer();
        int getSock(void);
    private:
        int sock;
        int mode;
        BIO * in_bio, * out_bio;
        SSL_CTX * ctx;
        SSL * ssl;
        void serveSecure(SSL * ssl);
};

#endif
