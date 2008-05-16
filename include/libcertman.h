/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#ifndef NGCM_H
#define NGCM_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 * @name ngcm_open
 * @short Open a secure certificate store
 * @param my_cert_store, (out) the certificate store
 * @return 0 on success, otherwise an error code
 */
extern int ngcm_open(X509_STORE** my_cert_store);

/**
 * @name ngcm_collect
 * @short Load and verify the certificates of the given domain. 
 * This function can be called multiple times.
 * @param domain, (in) logical name of the domain
 * @param my_cert_store, (in) the store where to add the certificates
 * @return 0 on success, otherwise an error code
 */
extern int ngcm_collect(const char* domain, X509_STORE* my_cert_store);

/**
 * @name ngcm_close
 * @short Close the certificate store
 * @param handle, (in) the handle to the store got from ngcm_open
 * @return 0 on success, otherwise an error code
 */
extern int ngcm_close(X509_STORE* my_cert_store);

#endif
