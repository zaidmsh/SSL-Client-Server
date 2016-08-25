#include <iostream>
#include <cstdlib>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>


#include "encrypt.hpp"


encrypt::encrypt(int mode){
    /* Initializing Openssl */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* Initializing SSL_CTX */
    switch(mode) {
        case ENCRYPT_SERVER:
            ctx = SSL_CTX_new(SSLv3_server_method());
            this->mode = mode;
            break;
        case ENCRYPT_CLIENT:
            ctx = SSL_CTX_new(SSLv3_client_method());
            this->mode = mode;
            break;
        default:
            std::cout << "Error: mode is invalid" << std::endl;
            std::exit(1);
    }
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        std::cout << "Error: cannot creaet new SSL.\n";
        std::exit(1);
    }
}

encrypt::encrypt() {

}

encrypt::~encrypt() {
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free_all(in_bio);
    BIO_free_all(out_bio);
}

bool encrypt::loadCertificates(const char * CertFile, const char * KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cout << "Private key does not match the public certificate\n";
        std::exit(1);
    }
}

bool encrypt::openConnection(const char * hostname, int port) {
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, hostname, &addr.sin_addr);
    switch (mode) {
        case ENCRYPT_SERVER:
        if (bind(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in))) {
            std::cout << "Error: Can't Bind socket\n";
            return false;
        }
        if (listen(sock, 10) != 0) {
            std::cout << "Error: Can't configure listening port\n";
            return false;
        }
        break;
        case ENCRYPT_CLIENT:
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            std::cout << "Error: Connection to server failed\n";
            return false;
        }
        break;
        default:
        std::cout << "Error: Host type unkown\n";
        return false;
    }
    return true;
}

bool encrypt::openBioConnection(const char * hostname, int port) {
    in_bio = BIO_new(BIO_s_mem());
    if (in_bio == NULL) {
        std::cout << "Error: cannot allocate read bio.\n";
        return false;
    }
    BIO_set_mem_eof_return(in_bio, -1);

    out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        std::cout << "Error: cannot allocate write bio.\n";
        return false;
    }
    BIO_set_mem_eof_return(out_bio, -1);

    SSL_set_bio(ssl, in_bio, out_bio);

    if(mode == ENCRYPT_SERVER) {
        SSL_set_accept_state(ssl);
    }
    else {
        SSL_set_connect_state(ssl);
    }
    //
    // BIO_get_ssl(bio, &ssl);
    // if (ssl == NULL) {
    //     std::cout << "SSL NULL\n";
    //     return false;
    // }
    // SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    // char host[BUF_SIZE];
    // snprintf(host, BUF_SIZE, "%s:%d", hostname, port);
    // std::cout << "host: " << host << std::endl;
    // BIO * acpt = BIO_new_accept(host);
    // BIO_set_accept_bios(acpt, bio);
    // if (BIO_do_accept(acpt) <= 0) {
    //     ERR_print_errors(acpt);
    //     return false;
    // }
    // bio = BIO_pop(acpt);
    // BIO_free_all(acpt);
    // if (BIO_do_handshake(bio) <= 0) {
    //     ERR_print_errors(bio);
    //     return false;
    // }
    return true;
}

bool encrypt::client() {
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        return false;
    } else {
        char * msg = "HELLO WORLD!!!";
        char buf[BUF_SIZE];
        int bytes;
        std::cout << "Connected with " << SSL_get_cipher(ssl) << "encryption\n";
        SSL_write(ssl, msg, strlen(msg));
        bytes = SSL_read(ssl, buf, BUF_SIZE);
        buf[bytes] = 0;
        std::cout << "Received from server: " << buf << std::endl;
    }
    return true;
}

bool encrypt::clientBio() {
    char buf[BUF_SIZE] = "Sending to server throught BIO\n";
    size_t len = strlen(buf);

    std::cout << "Message: " << buf << std::endl;
    std::cout << "Sending...\n";
    if (BIO_write(in_bio, buf, len) <= 0) {
        if (!BIO_should_retry(in_bio)) {
            ERR_print_errors(in_bio);
            return false;
        } else if (BIO_write(in_bio, buf, len) <= 0) {
            ERR_print_errors(in_bio);
            return false;
        }
    }
    std::cout << "Sent.\n";

    std::cout << "Receiving...\n";
    int read = BIO_read(out_bio, buf, BUF_SIZE);
    if (read == 0) {
        ERR_print_errors(out_bio);
        return false;
    } else if (read < 0) {
        if (!BIO_should_retry(out_bio)) {
            ERR_print_errors(out_bio);
            return false;
        } else {
            read = BIO_read(out_bio, buf, BUF_SIZE);
            if (read <= 0) {
                ERR_print_errors(out_bio);
                return false;
            }
        }
    }
    buf[read] = 0;
    std::cout << "Received: " << buf << std::endl;
    return true;
}

void encrypt::serve(SSL * ssl) {
    char buf[BUF_SIZE];
    char reply[BUF_SIZE];
    int sd, bytes;

    if (SSL_accept(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        return;
    } else {
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
            buf[bytes] = 0;
            std::cout << "Client message: " << buf << std::endl;
            snprintf(reply, BUF_SIZE, "Message received\n");
            SSL_write(ssl, reply, strlen(reply));
        } else {
            ERR_print_errors_fp(stderr);
            return;
        }
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
    }
}

bool encrypt::server() {
    while(1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *client_ssl;

        int client = accept(sock, (struct sockaddr *)&addr, &len);
        std::cout << "Connection: " << inet_ntoa(addr.sin_addr), ntohs(addr.sin_port);
        client_ssl = SSL_new(ctx);
        SSL_set_fd(client_ssl, client);
        serve(client_ssl);
    }
}

bool encrypt::serverBio() {
    char buf[BUF_SIZE];
    size_t len;

    std::cout << "Receiving...\n";
    int read = BIO_read(out_bio, buf, BUF_SIZE);
    if (read == 0) {
        ERR_print_errors(out_bio);
        return false;
    } else if (read < 0) {
        if (!BIO_should_retry(out_bio)) {
            ERR_print_errors(out_bio);
            return false;
        } else {
            read = BIO_read(out_bio, buf, BUF_SIZE);
            if (read <= 0) {
                ERR_print_errors(out_bio);
                return false;
            }
        }
    }
    buf[read] = 0;
    std::cout << "Received: " << buf << std::endl;

    strncpy(buf, "Received message through BIO\n", BUF_SIZE);
    std::cout << "Message: " << buf << std::endl;
    std::cout << "Sending...\n";
    if (BIO_write(in_bio, buf, len) <= 0) {
        if (!BIO_should_retry(in_bio)) {
            ERR_print_errors(in_bio);
            return false;
        } else if (BIO_write(in_bio, buf, len) <= 0) {
            ERR_print_errors(in_bio);
            return false;
        }
    }
    std::cout << "Sent.\n";
    return true;
}

bool encrypt::read(char * buf, std::size_t len) {
    int x = BIO_read(out_bio, buf, len);
    if (x == 0) {
        std::cout << "Error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        return false;
    } else if (x < 0) {
        if (!BIO_should_retry(out_bio)) {
            std::cout << "Error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
            return false;
        }
        return read(buf, len);
    }
    buf[x] = 0;
    return true;
}

bool encrypt::write(const char * buf, std::size_t len) {
    if (BIO_write(in_bio, buf, len) <= 0) {
        if (!BIO_should_retry(in_bio)) {
            std::cout << "Error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
            return false;
        }
        return write(buf, len);
    }
    return true;
}
