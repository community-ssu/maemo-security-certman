// -*- mode:c; tab-width:4; c-basic-offset:4; -*- 
/**
 \file libcertman.h
 \ingroup libcertman
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

/**
 * \brief Verify a certificate against a given certificate store
 * \param my_cert_store An X509 store
 * \param cert An X509 certificate
 * \returns 1 if the given certificate is valid and signed by one
 * of the certificates in the store, 0 otherwise.
 */
extern int ngsw_cert_is_valid(X509_STORE* my_cert_store, X509* cert);

/**
 * \def NGSW_CD_PRIVATE
 * \brief Create a new private domain, only modifiable by the 
 *        creating application (see NGSW security documentation
 *        about application identity)
 */
#define NGSW_CD_PRIVATE 0

/**
 * \def NGSW_CD_COMMON
 * \brief Create a new common domain, accessible for all applications
 */
#define NGSW_CD_COMMON 1


/**
 * \brief Open an existing domain or create a new one
 * \param name (in) logical name of the domain
 * \param flags (in) type of domain to open/create (see NGSW_CD_* flags)
 * \param handle (out) a handle to the domain
 * \return 0 on success, otherwise an error code
 */
extern int ngsw_certman_open_domain(const char* name_domain, int flags, int* handle);

/**
 * \brief Iterate through a domain
 * \param handle (in) a handle to the domain returned by 
 *                    \ref ngsw_certman_open_domain
 * \param cb_func (in) a callback function called once for each
 *                     certificate in the domain. The first parameter
 *                     is the domain handle, the second a X509* certificate
 *                     struct. If the callback returns a non-zero value,
 *                     the iteration is terminated. NOTE: the other functions
 *                     in this library must not be called in the callback
 *                     function.
 * \return 0 on success, otherwise an error code
 */
extern int ngsw_certman_iterate_domain(int the_domain, int cb_func(int,X509*));

/**
 * \brief Add a certificate into the domain
 * \param handle (in) a handle to the domain
 * \param cert (in) the certificate to be added
 * \return 0 on success, otherwise an error code. EACCESS
 * if the application does not have the power to modify
 * the domain.
 */
extern int ngsw_certman_add_cert(int to_domain, X509* cert);

/**
 * \brief Remove a certificate from the domain
 * \param handle (in) a handle to the domain
 * \param cert (in) the certificate to be removed
 * \return 0 on success, otherwise an error code. EACCESS
 * if the application does not have the power to modify
 * the domain.
 */
extern int ngsw_certman_rm_cert(int to_domain, X509* cert);

/**
 * \brief Close a domain
 * \param handle (in) a handle to the domain
 * \return 0 on success, otherwise and error code
 * 
 * Upon closing the changes are updated on the disk, if the
 * application has permissions to do that.
 */
extern int ngsw_certman_close_domain(int handle);


#endif
