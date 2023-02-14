/**
 * @file session_ctn_tls_60802.c
 * @author Adian Shubbar
 * @brief libnetconf2 TLS server session for tsn roles manipulation functions
 *
 */

#define _GNU_SOURCE

#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "log_p.h"

enum ROLES_60802
{
    Undefined,
    TruststoreAdminRole,
    KeystoreAdminRole,
    UserMappingAdminRole,
    RecoverySessionRole,
};

static enum ROLES_60802 get_role_60802(const ASN1_STRING *v)
{
    int i, n;
    char buf[80];
    const char *p;

    if (v == NULL)
        return 0;
    n = 0;
    p = (const char *)v->data;
    for (i = 0; i < v->length; i++)
    {
        if ((p[i] > '~') || ((p[i] < ' ') &&
                             (p[i] != '\n') && (p[i] != '\r')))
        {
        }
        else
        {
            buf[n] = p[i];
            n++;
        }
    }
    WRN(NULL, "Extension %s", buf);

    if (strcmp("TruststoreAdminRole", buf) == 0)
    {
        return TruststoreAdminRole;
    }
    else if (strcmp("KeystoreAdminRole", buf) == 0)
    {
        return KeystoreAdminRole;
    }
    else if (strcmp("UserMappingAdminRole", buf) == 0)
    {
        return UserMappingAdminRole;
    }
    else if (strcmp("RecoverySessionRole", buf) == 0)
    {
        return RecoverySessionRole;
    }
    else
    {
        return Undefined;
    }
}

int nc_tls_ctn_get_username_roles_from_cert_60802(X509 *client_cert, char **username)
{

    const STACK_OF(X509_EXTENSION) *exts = NULL;
    int num, i;
    exts = X509_get0_extensions(client_cert);
    if ((num = sk_X509_EXTENSION_num(exts)) <= 0)
    {
        WRN(NULL, "No extensions in certificate\n");
        return 1;
    }

    for (i = 0; i < num; i++)
    {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ex;

        ex = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ex);
        if (X509_EXTENSION_get_critical(ex))
        {
            if ((OBJ_obj2nid(obj) == NID_undef))
            {
                enum ROLES_60802 role = get_role_60802(X509_EXTENSION_get_data(ex));
                switch (role)
                {
                case TruststoreAdminRole:
                    *username = strdup("TruststoreAdminRole");
                    break;

                case KeystoreAdminRole:
                    *username = strdup("KeystoreAdminRole");
                    break;

                case UserMappingAdminRole:
                    *username = strdup("UserMappingAdminRole");
                    break;

                default:
                    ERR(NULL, "Undefined Role found");
                    return 1;
                }
            }
        }
    }

    return 0;
}
int is_recovery_session(X509 *client_cert)
{
    const STACK_OF(X509_EXTENSION) *exts = NULL;
    int num, i;
    exts = X509_get0_extensions(client_cert);
    if ((num = sk_X509_EXTENSION_num(exts)) <= 0)
    {
        WRN(NULL, "No extensions in certificate\n");
        return 1;
    }

    for (i = 0; i < num; i++)
    {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ex;

        ex = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ex);
        if (X509_EXTENSION_get_critical(ex))
        {
            if ((OBJ_obj2nid(obj) == NID_undef))
            {
                if (get_role_60802(X509_EXTENSION_get_data(ex)) == RecoverySessionRole)
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

int get_serial_number(X509 *client_cert, char **subject_IDevID)
{
    char *subject, *serial_num;
    subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
    serial_num = strstr(subject, "serialNumber=");
    if (!serial_num)
    {
        WRN(NULL, "Certificate does not include the serial number field.");
        free(subject);
        return 1;
    }
    serial_num += 14;
    if (strchr(serial_num, '/'))
    {
        *strchr(serial_num, '/') = '\0';
    }
    *subject_IDevID = strdup(serial_num);
    
    WRN(NULL, "serail number is  %s", subject_IDevID);
    free(subject);
    
return 0;

}