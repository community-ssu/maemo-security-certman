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

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * \def NGSW_CD_PRIVATE
 * \brief Private certificate domains can only be accessed by 
 *        one application, the one that has created them and
 *        owns them.
 */
#define NGSW_CD_PRIVATE 0

/**
 * \def NGSW_CD_COMMON
 * \brief Common certificate domain, accessible by all applications
 */
#define NGSW_CD_COMMON 1

/**
 * \typedef domain_handle
 * \brief A magic cookie reference to a domain opened by \ref
 * ngsw_certman_open_domain and to be used in the domain management 
 * functions.
 */
typedef void* domain_handle;

/**
 * \def NGSW_CM_DOMAIN_NONE
 * \brief The value a domain handle cannot have if its properly
 * opened.
 */
#define NGSW_CM_DOMAIN_NONE (void*)(0)


/// \name General certificate management functions
//@{

/**
 * \brief Open a secure certificate store
 * \param my_cert_store (out) the initial certificate store, 
 * contains the root X509 certificate from BB5. Should be NULL
 * when the function is called.
 * \returns 0 on success, otherwise an error code
 */
int ngsw_certman_open(X509_STORE** my_cert_store);

/**
 * \brief Load and verify the certificates of the given domain. 
 *        This function can be called multiple times.
 * \param domain (in) logical name of the domain
 * \param shared (in) if true, a shared domain is expected, otherwise
 *                    a private one
 * \param my_cert_store (in,out) the store where to add the certificates
 * \return 0 on success, otherwise an error code
 */
int ngsw_certman_collect(const char* domain, 
						 int shared, 
						 X509_STORE* my_cert_store);

/**
 * \brief Close the certificate store and release reserved resources
 * \param my_cert_store (in) the certificate store to be released
 * \return 0 on success, otherwise an error code
 */
int ngsw_certman_close(X509_STORE* my_cert_store);

//@}

/// \name Certificate domain management functions
//@{

/**
 * \brief Open an existing domain or create a new one
 * \param domain_name (in) logical name of the domain
 * \param flags (in) type of domain to open/create (see NGSW_CD_* flags)
 * \param handle (out) a handle to the domain to be used in subsequent calls
 * \return 0 on success, otherwise an error code
 */
int ngsw_certman_open_domain(const char* domain_name, 
							 int flags, 
							 domain_handle* handle);

/**
 * \brief Iterate through a domain
 * \param the_domain (in) a handle to the domain returned by 
 *        \ref ngsw_certman_open_domain
 * \param cb_func (in) a callback function called once for each
 *        certificate in the domain. The first parameter
 *        is the order number of the certificate in the domain
 *        (starting from 0), the second a pointer to a X509 certificate
 *        struct and the third is the given ctx pointer.
 *        If the callback returns other than 0 or -1, the iteration is 
 *        terminated. If the callback returns 0, the certificate 
 *        is released right after the callback.
 * \param ctx (in) a void pointer passed to the callback function
 * \return if >= 0, the index where iteration terminated,
 *         if < 0, an error code
 * \warning If you modify the domain inside the callback function
 *        with "add cert" or "rm cert", the results may be quite unpredictable.
 *        So don't.
 */
int ngsw_certman_iterate_domain(domain_handle the_domain, 
								int cb_func(int,X509*,void*), 
								void* ctx);

/**
 * \brief Add a certificate into the domain
 * \param to_domain (in) a handle to the domain
 * \param cert (in) the certificate to be added
 * \return 0 on success, otherwise an error code. EACCESS
 * if the application does not have the power to modify
 * the domain.
 */
int ngsw_certman_add_cert(domain_handle to_domain, X509* cert);

/**
 * \brief Remove a certificate from the domain
 * \param from_domain (in) 
 * \param pos (in) the order number of the certificate to be removed
 * \return 0 on success, otherwise an error code. EACCESS
 * if the application does not have the power to modify
 * the domain.
 */
int ngsw_certman_rm_cert(domain_handle from_domain, int pos);

/**
 * \brief Return the number of certificates in a domain
 * \param in_domain (in) a handle to the domain
 * \return >= 0 on success, otherwise -1
 */
int ngsw_certman_nbrof_certs(domain_handle in_domain);

/**
 * \brief Close a domain
 * \param handle (in) a handle to the domain
 * \return 0 on success, otherwise and error code
 * 
 * Upon closing the changes are updated on the disk, if the
 * application has permissions to do that.
 */
int ngsw_certman_close_domain(domain_handle handle);

//@}

#ifdef	__cplusplus
} // extern "C"
#endif

#endif
