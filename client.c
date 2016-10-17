#include <stdio.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"

#define SERVER "192.168.56.101"
#define PORT   "9876"

int
main(int argc, char **argv)
{
    SSL *my_ssl;
    SSL_CTX *my_ctx;
    BIO     *my_bio;
    int     rv;
    char    bio_write[1024];
    char    bio_read[1024];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();

    my_ctx = SSL_CTX_new(TLSv1_client_method());

    if ((my_ssl = SSL_new(my_ctx)) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    /* set up the socket */
    if ((my_bio = BIO_new_connect("127.0.0.1:9876")) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    /* bind */
    if (BIO_do_connect(my_bio) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    SSL_set_bio(my_ssl, my_bio, my_bio);

    if (SSL_connect(my_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    for (;;) {
        rv = SSL_read(my_ssl, bio_read, 1024);
        if (rv <= 0) {
            rv = SSL_get_error(my_ssl, rv);
            if (rv == SSL_ERROR_WANT_READ) {
                fprintf(stdout, "Failed read: rereading...\n");
                continue;
            }
            break;
        }
        printf("Message: %s\n", bio_read);
        fprintf(stdout, "Done\n");
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
        if (SSL_get_error(my_ssl, rv) == SSL_ERROR_WANT_WRITE) {
            rv = SSL_read(my_ssl, bio_read, 1024);
        }
        break;
    }

    SSL_free(my_ssl);
    SSL_CTX_free(my_ctx);
    return 0;
}
