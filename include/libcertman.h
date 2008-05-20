// -*- mode:c; tab-width:4; c-basic-offset:4; -*- 
/**
 \file libcertman.h
 \ingroup libcertman Certificate manager
 \brief The certman library low-level API

  The functions for accessing certificate stores as openSSL's X509
  data structures.
*/

#ifndef NGCM_H
#define NGCM_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>


/**
 * \brief Open a secure certificate store
 * \param my_cert_store (out) the initial certificate store, 
 * contains the root X509 certificate from BB5. Should be NULL
 * when the function is called.
 * \returns 0 on success, otherwise an error code
 */

extern int ngsw_certman_open(X509_STORE** my_cert_store);

/**
 * \brief Load and verify the certificates of the given domain. 
 * This function can be called multiple times.
 * \param domain (in) logical name of the domain
 * \param my_cert_store (in,out) the store where to add the certificates
 * \return 0 on success, otherwise an error code
 */

extern int ngsw_certman_collect(const char* domain, X509_STORE* my_cert_store);

/**
 * \brief Close the certificate store and release reserved resources
 * \param my_cert_store (in) the certificate store to be released
 * \return 0 on success, otherwise an error code
 */
extern int ngsw_certman_close(X509_STORE* my_cert_store);

#endif
