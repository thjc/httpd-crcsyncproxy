#ifndef SSL_TOOLKIT_COMPAT_H
#define SSL_TOOLKIT_COMPAT_H

/*
 * this header file provides a compatiblity layer
 * between OpenSSL and RSA sslc
 */

#ifdef OPENSSL_VERSION_NUMBER

/*
 * rsa sslc uses incomplete types for most structures
 * so we macroize for OpenSSL those which cannot be dereferenced
 * using the same sames as the sslc functions
 */

#define EVP_PKEY_key_type(k)              (EVP_PKEY_type(k->type))

#define X509_NAME_get_entries(xs)         (xs->entries)
#define X509_REVOKED_get_serialNumber(xs) (xs->serialNumber)

#define X509_get_signature_algorithm(xs) (xs->cert_info->signature->algorithm)
#define X509_get_key_algorithm(xs)       (xs->cert_info->key->algor->algorithm)

#define X509_NAME_ENTRY_get_data_ptr(xs) (xs->value->data)
#define X509_NAME_ENTRY_get_data_len(xs) (xs->value->length)

#define SSL_CTX_get_extra_certs(ctx)       (ctx->extra_certs)
#define SSL_CTX_set_extra_certs(ctx,value) {ctx->extra_certs = value;}

#define SSL_CIPHER_get_name(s)             (s->name)
#define SSL_CIPHER_get_valid(s)            (s->valid)

#define SSL_SESSION_get_session_id(s)      (s->session_id)
#define SSL_SESSION_get_session_id_length(s) (s->session_id_length)

/*
 * Support for retrieving/overriding states
 */
#ifndef SSL_get_state
#define SSL_get_state(ssl) SSL_state(ssl)
#endif

#define SSL_set_state(ssl,val) (ssl)->state = val

#define MODSSL_BIO_CB_ARG_TYPE const char

#define modssl_X509_verify_cert(c) X509_verify_cert(c)

#else /* RSA sslc */

#ifndef STACK_OF
#define STACK_OF(type) STACK
#endif

#define MODSSL_BIO_CB_ARG_TYPE char

#define modssl_X509_verify_cert(c) X509_verify_cert(c, NULL)

#if SSLC_VERSION < 0x2000

#define X509_STORE_CTX_set_depth(st, d)    
#define X509_CRL_get_lastUpdate(x) ((x)->crl->lastUpdate)
#define X509_CRL_get_nextUpdate(x) ((x)->crl->nextUpdate)
#define X509_CRL_get_REVOKED(x)    ((x)->crl->revoked)
#define X509_REVOKED_get_serialNumber(xs) (xs->serialNumber)

#endif

/* BEGIN GENERATED SECTION */
#define sk_SSL_CIPHER_free sk_free
#define sk_SSL_CIPHER_dup sk_dup
#define sk_SSL_CIPHER_num sk_num
#define sk_SSL_CIPHER_find(st, data) sk_find(st, (void *)data)
#define sk_SSL_CIPHER_value (SSL_CIPHER *)sk_value
#define sk_X509_num sk_num
#define sk_X509_value (X509 *)sk_value
#define sk_X509_INFO_value (X509_INFO *)sk_value
#define sk_X509_INFO_num sk_num
#define sk_X509_INFO_new_null sk_new_null
#define sk_X509_NAME_num sk_num
#define sk_X509_NAME_push(st, data) sk_push(st, (void *)data)
#define sk_X509_NAME_value (X509_NAME *)sk_value
#define sk_X509_NAME_free sk_free
#define sk_X509_NAME_new sk_new
#define sk_X509_NAME_find(st, data) sk_find(st, (void *)data)
#define sk_X509_NAME_ENTRY_num sk_num
#define sk_X509_NAME_ENTRY_value (X509_NAME_ENTRY *)sk_value
#define sk_X509_NAME_set_cmp_func sk_set_cmp_func
#define sk_X509_REVOKED_num sk_num
#define sk_X509_REVOKED_value (X509_REVOKED *)sk_value
#define sk_X509_pop_free sk_pop_free
/* END GENERATED SECTION */

#endif /* OPENSSL_VERSION_NUMBER */

#endif /* SSL_TOOLKIT_COMPAT_H */
