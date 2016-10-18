#include <stdio.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"

#define SERVER "127.0.0.1"
#define PORT   "9876"

void err_call(const char *);

int
main(int argc, char **argv)
{
    SSL *my_ssl;
    SSL_CTX *my_ctx;
    BIO     *my_bio, *tmp_bio;
    int     rv;
    char    *buf_write = "HELLO! I'm a client";
    char    buf_read[1024];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();

    my_ctx = SSL_CTX_new(TLSv1_client_method());

    /* set up the socket */
    if ((my_bio = BIO_new_ssl_connect(my_ctx)) == NULL) {
        err_call("Error: Creating connect BIO\n");
    }

    BIO_set_conn_hostname(my_bio, "127.0.0.1:9876");

    fprintf(stdout, "Connecting...\n");
    /* bind */
    if (BIO_do_connect(my_bio) <= 0) {
        err_call("Error: Creating connect BIO socket\n");
    }


    if (BIO_do_handshake(my_bio) <= 0) {
        err_call("Error: SSL handshake\n");
    }

    BIO_get_ssl(my_bio, &my_ssl);
    printf("Connection made with [version,cipher]: [%s,%s]\n",SSL_get_version(my_ssl),SSL_get_cipher(my_ssl));
    // receiving encrypted message from server
    for (;;) {
        fprintf(stdout, "Waiting for server's message...\n");
        rv = BIO_read(my_bio, buf_read, 1024);
        if (rv <= 0) {
            if (BIO_should_retry(my_bio)) {
                fprintf(stderr, "Error: BIO_read DELAY, rereading...\n");
                sleep(1);
                continue;
            } else {
                fprintf(stderr, "Error: failed BIO_read()\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        printf("Server's message: %s\n", buf_read);
        break;
    }

    tmp_bio = BIO_pop(my_bio); // pop bio type socket connect

    if (BIO_do_handshake(tmp_bio) <= 0) {
        err_call("Error: SSL handshake\n");
    }

    // sending unencrypted message to server
    for (;;) {
        fprintf(stdout, "Sending to the server...\n");
        rv = BIO_write(tmp_bio, buf_write, strlen(buf_write));
        if (rv <= 0) {
            if (BIO_should_retry(tmp_bio)) {
                fprintf(stderr, "Erro: BIO_write DELAY, rewriting...\n");
                sleep(1);
                continue;
            } else {
                fprintf(stderr, "Error: failed BIO_write()\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        fprintf(stdout, "BIO_write()\n");
        break;
    }

    for (;;) {
        fprintf(stdout, "Waiting for server's response ...\n");
        rv = BIO_read(tmp_bio, buf_read, 1024);
        if (rv <= 0) {
            if (BIO_should_retry(tmp_bio)) {
                fprintf(stderr, "Error: BIO_read DELAY, rereading...\n");
                sleep(1);
                continue;
            } else {
                fprintf(stderr, "Error: failed BIO_read()\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        buf_read[rv] = 0;
        printf("Message: %s\n", buf_read);
        break;
    }

    BIO_free_all(tmp_bio);
    BIO_ssl_shutdown(my_bio);
    BIO_free_all(my_bio);
    SSL_CTX_free(my_ctx);
    return 0;
}

void
err_call(const char *msg)
{
    fprintf(stderr, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}
