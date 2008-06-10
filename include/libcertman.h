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
 *        This function can be called multiple times.
 * \param domain (in) logical name of the domain
 * \param shared (in) if true, a shared domain is expected, otherwise
 *                    a private one
 * \param my_cert_store (in,out) the store where to add the certificates
 * \return 0 on success, otherwise an error code
 */
extern int ngsw_certman_collect(const char* domain, 
								int shared, 
								X509_STORE* my_cert_store);

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
 * \typedef domain_handle
 * \brief A magic cookie type to a domain opened by \ref ngsw_certman_open_domain
 * and to be used in the domain management functions.
 */
typedef void* domain_handle;


/**
 * \brief Open an existing domain or create a new one
 * \param domain_name (in) logical name of the domain
 * \param flags (in) type of domain to open/create (see NGSW_CD_* flags)
 * \param handle (out) a handle to the domain to be used in subsequent calls
 * \return 0 on success, otherwise an error code
 */
extern int ngsw_certman_open_domain(
	const char* domain_name, 
	int flags, 
	domain_handle* handle);

/**
 * \brief Iterate through a domain
 * \param the_domain handle (in) a handle to the domain returned by 
 *        \ref ngsw_certman_open_domain
 * \param cb_func (in) a callback function called once for each
 *        certificate in the domain. The first parameter
 *        is the domain handle, the second a X509* certificate
 *        struct. If the callback returns a non-zero value,
 *        the iteration is terminated.
 * \param ctx (in) a void pointer passed to the callback function
 * \return if >= 0, the index where iteration terminated,
 *         if < 0, an error code
 * \warning If you modify the domain inside the callback function
 *        with "add cert" or "rm cert", the results may be quite unpredictable.
 *        So don't.
 */
extern int ngsw_certman_iterate_domain(
	domain_handle the_domain, 
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
extern int ngsw_certman_add_cert(domain_handle to_domain, X509* cert);

/**
 * \brief Remove a certificate from the domain
 * \param from_domain (in) 
 * \param pos (in) the order number of the certificate to be removed
 * \return 0 on success, otherwise an error code. EACCESS
 * if the application does not have the power to modify
 * the domain.
 */
extern int ngsw_certman_rm_cert(domain_handle from_domain, int pos);

/**
 * \brief Return the number of certificates in the open domain
 * \param in_domain (in) a handle to the domain
 * \return >= 0 on success, otherwise -1
 */
extern int ngsw_certman_nbrof_certs(domain_handle in_domain);

/**
 * \brief Close a domain
 * \param handle (in) a handle to the domain
 * \return 0 on success, otherwise and error code
 * 
 * Upon closing the changes are updated on the disk, if the
 * application has permissions to do that.
 */
extern int ngsw_certman_close_domain(domain_handle handle);


#endif
