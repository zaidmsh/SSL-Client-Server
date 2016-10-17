#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"

#define SERVER "192.168.56.101"
#define PORT   "9876"

volatile sig_atomic_t stop = 0;

void
sig_handler(int signum)
{
    if (signum == SIGINT) {
        printf("ctrl-C\n");
        stop = 1;
    }
}

int
main(int argc, char **argv)
{
    SSL *my_ssl;
    SSL_CTX *my_ctx;
    BIO     *my_bio, *client_bio;
    int     rv;
    char    *buf = "HELLO! Im the server\n";

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
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    SSL_CTX_use_certificate_file(my_ctx, argv[1], SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(my_ctx, argv[1], SSL_FILETYPE_PEM);

    if (!SSL_CTX_check_private_key(my_ctx)) {
        fprintf(stderr, "private won't work\n");
        exit(-1);
    }

    /* set up the socket */
    if ((my_bio = BIO_new_accept(PORT)) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    /* bind */
    if (BIO_do_accept(my_bio) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    while (!stop) {
        if (BIO_do_accept(my_bio) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(-1);
        }

        client_bio = BIO_pop(my_bio);

        if ((my_ssl = SSL_new(my_ctx)) == NULL) {
            ERR_print_errors_fp(stderr);
            exit(-1);
        }

        SSL_set_bio(my_ssl, client_bio, client_bio);

        if (SSL_accept(my_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(-1);
        }

        for (;;) {
            rv = SSL_write(my_ssl, buf, strlen(buf));
            if (rv <= 0) {
                rv = SSL_get_error(my_ssl, rv);
                if (rv == SSL_ERROR_WANT_WRITE) {
                    fprintf(stdout, "Failed write: rewriting...\n");
                    continue;
                }
                break;
            }
            fprintf(stdout, "SSL_write()\n");
            break;
        }

        rv = SSL_shutdown(my_ssl);

        switch (rv) {
        case 0:
            SSL_shutdown(my_ssl);
            fprintf(stdout, "calling SSL_shutdown() again\n");
            break;
        case 1:
            fprintf(stdout, "SSL_shutdown() successful\n");
            break;
        default:
            fprintf(stdout, "SSL_shutdown() Fatal error\n");
            break;
        }
        SSL_free(my_ssl);
    }

    SSL_CTX_free(my_ctx);
    BIO_free(my_bio);
    return 0;
}
