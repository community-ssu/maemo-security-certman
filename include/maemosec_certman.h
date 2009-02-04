/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*-
 *
 * This file is part of maemo-security-certman
 *
 * Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Juhani Mäkelä <ext-juhani.3.makela@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**
 \file maemosec_certman.h
 \ingroup libcertman
 \brief The certman library low-level API

  The functions for accessing certificate stores as openSSL's X509
  data structures.

*/

#ifndef MAEMOSEC_CERTMAN_H
#define MAEMOSEC_CERTMAN_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include "maemosec_common.h"

#ifdef	__cplusplus
extern "C" {
#endif

	/**
	 * \def MAEMOSEC_CERTMAN_DOMAIN_PRIVATE
	 * \brief Private certificate domains can only be accessed by 
	 *        one application, the one that has created them and
	 *        owns them.
	 */
    #define MAEMOSEC_CERTMAN_DOMAIN_PRIVATE 0
	
	/**
	 * \def MAEMOSEC_CERTMAN_DOMAIN_SHARED
	 * \brief Common certificate domain, accessible by all applications
	 */
    #define MAEMOSEC_CERTMAN_DOMAIN_SHARED 1
	
	/**
	 * \typedef domain_handle
	 * \brief A magic cookie reference to a domain opened by \ref
	 * maemosec_certman_open_domain and to be used in the domain management 
	 * functions.
	 */
	typedef void* domain_handle;

	/**
	 * \def MAEMOSEC_CERTMAN_DOMAIN_NONE
	 * \brief The value a domain handle cannot have if its properly
	 * opened.
	 */
    #define MAEMOSEC_CERTMAN_DOMAIN_NONE (void*)(0)

    #define MAEMOSEC_KEY_ID_LEN SHA_DIGEST_LENGTH
	typedef unsigned char maemosec_key_id [MAEMOSEC_KEY_ID_LEN];

    #define MAEMOSEC_KEY_ID_STR_LEN 2*SHA_DIGEST_LENGTH + 1

    /**
	 * \brief Convert a key id value to string
	 * \param key_id Key id as a byte array
	 * \param to_this A buffer to hold the default string
	 * \param max_len Size of the buffer, must be >= MAEMOSEC_KEY_ID_STR_LEN
	 * \returns 0 on success, otherwise an error code
	 */
	int maemosec_certman_key_id_to_str(maemosec_key_id key_id,
									   char* to_buf,
									   unsigned max_len);

    /**
	 * \brief Convert a string into a key id
	 * \param from_str The string presentation
	 * \param to_this Key id as a byte array
	 * \returns 0 on success, otherwise an error code
	 */
	int maemosec_certman_str_to_key_id(char* from_str,
									   maemosec_key_id key_id);


/// \name General certificate management functions
//@{

    /**
	 * \brief Open a secure certificate store
	 * \param my_cert_store (out) the initial certificate store, 
	 * contains the root X509 certificate from BB5. Should be NULL
	 * when the function is called.
	 * \returns 0 on success, otherwise an error code
	 */
	int maemosec_certman_open(X509_STORE** my_cert_store);

	/**
	 * \brief Load and verify the certificates of the given domain. 
	 *        This function can be called multiple times.
	 * \param domain (in) logical name of the domain
	 * \param shared (in) if true, a shared domain is expected, otherwise
	 *                    a private one
	 * \param my_cert_store (in,out) the store where to add the certificates
	 * \return 0 on success, otherwise an error code
	 */
	int maemosec_certman_collect(const char* domain, 
								 int shared, 
								 X509_STORE* my_cert_store);

	/**
	 * \brief Close the certificate store and release reserved resources
	 * \param my_cert_store (in) the certificate store to be released
	 * \return 0 on success, otherwise an error code
	 */
	int maemosec_certman_close(X509_STORE* my_cert_store);

	//@}

	/// \name Certificate domain management functions
	//@{

	/**
	 * \brief Get a list of existing domains
	 * \param flags (in) the type of domains to iterate (shared, private)
	 * \param cb_func (in) a callback function called once for each
	 *        domain. Parameters: order number, domain name, domain type 
	 *        and userdata pointer.
	 * \param ctx (in) a void pointer passed to the callback function
	 * \return if >= 0, the index where iteration terminated,
	 *         if < 0, an error code
	 * \warning If you modify the domain inside the callback function
	 *        with "add cert" or "rm cert", the results may be quite unpredictable.
	 *        So don't.
	 */
	int maemosec_certman_iterate_domains(int flags,
										 maemosec_callback* cb_func,
										 void* ctx);

	/**
	 * \brief Open an existing domain or create a new one
	 * \param domain_name (in) logical name of the domain
	 * \param flags (in) type of domain to open/create (see MAEMOSEC_CD_* flags)
	 * \param handle (out) a handle to the domain to be used in subsequent calls
	 * \return 0 on success, otherwise an error code
	 */
	int maemosec_certman_open_domain(const char* domain_name, 
									 int flags, 
									 domain_handle* handle);

	/**
	 * \brief Iterate through all certificates in a domain
	 * \param the_domain (in) a handle to the domain returned by 
	 *        \ref maemosec_certman_open_domain
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
	int maemosec_certman_iterate_certs(domain_handle the_domain, 
									   int cb_func(int, X509*, void*), 
									   void* ctx);


	int maemosec_certman_load_cert(domain_handle the_domain, 
								   maemosec_key_id with_id, 
								   X509** cert);

	/**
	 * \brief Add a certificate into the domain
	 * \param to_domain (in) a handle to the domain
	 * \param cert (in) the certificate to be added
	 * \return 0 on success, otherwise an error code. EACCESS
	 * if the application does not have the power to modify
	 * the domain.
	 */
	int maemosec_certman_add_cert(domain_handle to_domain, X509* cert);

	/**
	 * \brief Add a certificate into the domain
	 * \param to_domain (in) a handle to the domain
	 * \param cert_files (in) files from which the certificate are to be added
	 * \param count (in) how many file names there are in the list. A NULL also
	 *        terminates the list
	 * \return The number of certificates successfully added.
	 */
	int maemosec_certman_add_certs(domain_handle to_domain, char* cert_files[], unsigned count);


	/**
	 * \brief Remove a certificate from the domain
	 * \param from_domain (in) 
	 * \param key_id (in) The public key id of the certificate
	 * \return 0 on success, otherwise an error code. EACCESS
	 * if the application does not have the power to modify
	 * the domain.
	 */
	int maemosec_certman_rm_cert(domain_handle from_domain, maemosec_key_id key_id);

	/**
	 * \brief Return the number of certificates in a domain
	 * \param in_domain (in) a handle to the domain
	 * \return >= 0 on success, otherwise -1
	 */
	int maemosec_certman_nbrof_certs(domain_handle in_domain);

	/**
	 * \brief Close a domain
	 * \param handle (in) a handle to the domain
	 * \return 0 on success, otherwise and error code
	 * 
	 * Upon closing the changes are updated on the disk, if the
	 * application has permissions to do that.
	 */
	int maemosec_certman_close_domain(domain_handle handle);

	/*
	 * TODO: Documentation
	 */

	int maemosec_certman_get_key_id(X509* of_cert, maemosec_key_id to_this);

	int maemosec_certman_store_key(maemosec_key_id with_id, 
								   EVP_PKEY* the_key, 
								   char* with_passwd);

	int maemosec_certman_retrieve_key(maemosec_key_id with_id, 
									  EVP_PKEY** the_key, 
									  char* with_passwd);

	int maemosec_certman_iterate_keys(maemosec_callback* cb_func, void* ctx);

	int maemosec_certman_get_nickname(X509* of_cert, char* to_buf, unsigned buf_len);


//@}

#ifdef	__cplusplus
} // extern "C"
#endif

#endif
