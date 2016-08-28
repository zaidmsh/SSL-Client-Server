#include <iostream>
#include <cstdlib>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "secure.hpp"

secure::secure(int mode){
    /* Initializing Openssl */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* Initializing SSL_CTX */
    switch(mode) {
        case SECURE_SERVER:
            ctx = SSL_CTX_new(SSLv3_server_method());
            this->mode = mode;
            break;
        case SECURE_CLIENT:
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

secure::~secure() {
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free_all(in_bio);
    BIO_free_all(out_bio);
}

bool secure::loadCertificates(const char * CertFile, const char * KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cout << "Private key does not match the public certificate\n";
        return false;
    }
    return true;
}

bool secure::openConnection(const char * hostname, int port) {
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, hostname, &addr.sin_addr);
    switch (mode) {
        case SECURE_SERVER:
        if (bind(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in))) {
            std::cout << "Error: Can't Bind socket\n";
            return false;
        }
        if (listen(sock, 10) != 0) {
            std::cout << "Error: Can't configure listening port\n";
            return false;
        }
        break;
        case SECURE_CLIENT:
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

bool secure::nonSecureClient() {
    char message[BUF_SIZE] = "HELLO WORLD!!";
    int sent = send(sock, message, BUF_SIZE, 0);
    if (send <= 0) {
        std::cout << "Send failed\n";
        return false;
    }
    int received = recv(sock, message, BUF_SIZE, 0);
    if (received <= 0) {
        std::cout << "recv failed\n";
        return false;
    }
    message[received] = 0;
    std::cout << "Server response: " << message << std::endl;
    return true;
}

bool secure::secureClient() {
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        return false;
    } else {
        char * msg = "HELLO WORLD!!!";
        char buf[BUF_SIZE];
        int bytes;
        std::cout << "Connected with " << SSL_get_cipher(ssl) << "secureion\n";
        SSL_write(ssl, msg, strlen(msg));
        bytes = SSL_read(ssl, buf, BUF_SIZE);
        buf[bytes] = 0;
        std::cout << "Received from server: " << buf << std::endl;
    }
    return true;
}

void secure::serveSecure(SSL * ssl) {
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

bool secure::nonSecureServer() {
    struct sockaddr_in client;
    socklen_t len = sizeof(struct sockaddr);
    int client_sock = accept(sock, (struct sockaddr *)&client, &len);
    if (client_sock < 0) {
        std::cout << "Accept failed\n";
        close(client_sock);
        return false;
    }
    char message[BUF_SIZE];
    int read_size = recv(client_sock, message, BUF_SIZE, 0);
    if (read_size <= 0) {
        std::cout << "Receive failed\n";
        close(client_sock);
        return false;
    }
    std::cout << "Client message: " << message << std::endl;
    strncpy(message, "Message Received\n", BUF_SIZE);
    int received = write(client_sock, message, BUF_SIZE);
    if (received <= 0) {
        std::cout << "Sending to client failed\n";
        close(client_sock);
        return false;
    }
    close(client_sock);
}

bool secure::secureServer() {
    while(1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *client_ssl;

        int client = accept(sock, (struct sockaddr *)&addr, &len);
        std::cout << "Connection: " << inet_ntoa(addr.sin_addr), ntohs(addr.sin_port);
        client_ssl = SSL_new(ctx);
        SSL_set_fd(client_ssl, client);
        servesecure(client_ssl);
    }
}

int secure::getSock(void) {
    return sock;
}
