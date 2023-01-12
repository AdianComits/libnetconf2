#ifndef SESSION_CTN_TLS_60802_H   /* Include guard */
#define SESSION_CTN_TLS_60802_H

#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int nc_tls_ctn_get_username_roles_from_cert_60802(X509 *client_cert, char **username);

#endif // SESSION_CTN_TLS_60802_H
