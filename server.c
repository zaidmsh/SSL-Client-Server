#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"

#define SERVER "192.168.56.101"
#define PORT   "9876"

volatile sig_atomic_t stop = 0;

void err_call(const char *);
void sig_handler(int);


int
main(int argc, char **argv)
{
    SSL *my_ssl;
    SSL_CTX *my_ctx;
    BIO     *my_bio, *cbio, *sbio, *tmp_bio;
    int     rv;
    char    *buf_write = "HELLO! Im the server. Send your message\n";
    char    buf_read[1024];

    if (argc < 2) {
        fprintf(stderr, "Cert file not provided\n");
        exit(-1);
    }

    signal(SIGINT, sig_handler);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();

    my_ctx = SSL_CTX_new(TLSv1_server_method());
    if (my_ctx == NULL) {
        err_call("Error: creating SSL_CTX\n");
    }

    if (!SSL_CTX_use_certificate_file(my_ctx, argv[1], SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(my_ctx, argv[1], SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(my_ctx)) {
        err_call("Error: setting up SSL_CTX\n");
    }

    // setup a server bio
    sbio = BIO_new_ssl(my_ctx, 0);

    BIO_get_ssl(sbio, &my_ssl);
    if (my_ssl == NULL) {
        err_call("Error: Can't locate SSL pointer\n");
    }
    /* set up the socket */
    if ((my_bio = BIO_new_accept(PORT)) == NULL) {
        err_call("Error: creating an accept BIO\n");
    }

    BIO_set_accept_bios(my_bio, sbio);

    /* setup accept bio */
    if (BIO_do_accept(my_bio) <= 0) {
        err_call("Error: creating accept BIO socket\n");
    }

    while (!stop) {
        // wait for incoming connections
        fprintf(stdout, "Waiting for a client...\n");
        if (BIO_do_accept(my_bio) <= 0) {
            err_call("Error: in connection\n");
        }

        cbio = BIO_pop(my_bio);

        if (BIO_do_handshake(cbio) <= 0) {
            err_call("Error: SSL handshake\n");
        }

        // sending encrypted message to client
        for (;;) {
            fprintf(stdout, "Sending to the client...\n");
            rv = BIO_write(cbio, buf_write, strlen(buf_write));
            if (rv <= 0) {
                if (BIO_should_retry(cbio)) {
                    fprintf(stderr, "Erro: BIO_write DELAY, rewriting...\n");
                    sleep(1);
                    continue;
                } else {
                    fprintf(stderr, "Error: failed BIO_write()\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }
            }
            fprintf(stdout, "BIO_write() done\n");
            break;
        }

        tmp_bio = BIO_pop(cbio); // pop bio type socket

        // receiving unencrypted message from client
        for (;;) {
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
            fprintf(stdout, "BIO_read()\n");
            break;
        }

        // send unencrypted message to client
        buf_write = strdup("Your message has been received");
        for (;;) {
            fprintf(stdout, "Sending to the client...\n");
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
        free(buf_write);
        BIO_free_all(tmp_bio);
        BIO_free_all(cbio);
    }

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

void
sig_handler(int signum)
{
    if (signum == SIGINT) {
        printf("ctrl-C\n");
        stop = 1;
    }
}
