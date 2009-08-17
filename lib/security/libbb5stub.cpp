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

#include <string.h>
#include <sys/time.h>
#include <sys/fcntl.h>

extern "C" {
#include "libbb5stub.h"
}

#include <errno.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "maemosec_common.h"

static const char root_crt_name [] = "/etc/certs/trusted/root.ca";
static const char root_key_name [] = "/etc/certs/trusted/root.key";

static X509_STORE* root_store = NULL;
static X509*       root_crt = NULL;
static EVP_PKEY*   root_key = NULL;


static void
load_root_certificate(X509_STORE* to_this)
{
	X509_LOOKUP *lookup = NULL;
	int rc;
	
	lookup = X509_STORE_add_lookup(to_this, X509_LOOKUP_file());
	if (lookup == NULL) {
		MAEMOSEC_ERROR("cannot add lookup");
		// print_openssl_errors();
		goto end;
	}
		
	rc = X509_LOOKUP_load_file(
		lookup, 
		root_crt_name,
		X509_FILETYPE_PEM);

	if (rc == 0) {
		MAEMOSEC_DEBUG(1, "cannot load root certificate from '%s'", root_crt_name);
	} else {
		X509_OBJECT* obj;
		MAEMOSEC_DEBUG(1, "loaded root ca from '%s'", root_crt_name);
		obj = sk_X509_OBJECT_value(to_this->objs, 0);
		if (obj && obj->type == X509_LU_X509)
			root_crt = obj->data.x509;
		else
			MAEMOSEC_ERROR("cannot find root certificate");
	}
  end:
	;
}


static void
load_root_key(void)
{
	BIO* keyfile = NULL;

	keyfile = BIO_new(BIO_s_file());

	if (!keyfile) {
		MAEMOSEC_ERROR("cannot create BIO");
		return;
	}
	
	// TODO: there are many different formats for keys
	if (BIO_read_filename(keyfile, root_key_name) <= 0) {
		MAEMOSEC_ERROR("cannot load root CA key from '%s' (%s)", 
					   root_key_name, strerror(errno));
		// print_openssl_errors();
		return;
	}
	root_key = PEM_read_bio_PrivateKey(keyfile, NULL, NULL, NULL);
	if (!root_key) {
		MAEMOSEC_ERROR("Cannot load private key from '%s'", root_key_name);
	} else
		MAEMOSEC_DEBUG(1, "loaded root key from '%s'", root_key_name);
	BIO_free(keyfile);
}

extern "C" {

	void
	bb5_init(void)
	{
		struct timeval now;

		MAEMOSEC_DEBUG(1, "%s: enter", __func__);
		// CRYPTO_malloc_init()) -- Not needed but in Win32
		// OPENSSL_config(NULL);
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		// RSA_set_default_method(RSA_PKCS1_SSLeay());

		root_store = X509_STORE_new();
		if (root_store == NULL) {
			MAEMOSEC_ERROR("cannot create X509 store");
			// print_openssl_errors();
			return;
		}
		load_root_certificate(root_store);
		load_root_key();

		gettimeofday(&now, NULL);
		srand(now.tv_usec);
		MAEMOSEC_DEBUG(1, "%s: exit", __func__);
	}


	void
	bb5_finish(void)
	{
		MAEMOSEC_DEBUG(1, "%s: enter", __func__);
		if (root_key) {
			EVP_PKEY_free(root_key);
			root_key = NULL;
		}
		if (root_store) {
			X509_STORE_free(root_store);
			root_store = NULL;
			root_crt = NULL;
		}
		MAEMOSEC_DEBUG(1, "%s: middle", __func__);
		RAND_cleanup();
		EVP_cleanup();
		X509_TRUST_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();
		MAEMOSEC_DEBUG(1, "%s: exit", __func__);
	}


	X509*
	bb5_get_cert(int pos)
	{
		if (NULL == root_crt)
			bb5_init();
		return(root_crt);
	}


	int
	bb5_rsakp_sign(EVP_MD_CTX* ctx, unsigned char* md, size_t maxlen)
	{
		int rc;
		unsigned int signlen = 0;
		unsigned char lmd[1024];

		if (!root_key) {
			MAEMOSEC_ERROR("cannot sign: no private key");
			return(0);
		}
		
		rc = EVP_SignFinal(ctx, lmd, &signlen, root_key);
		if (rc != 1) {
			MAEMOSEC_ERROR("signing failed");
			// print_openssl_errors();
			return(0);
		}
		if (signlen <= maxlen) {
			memcpy(md, lmd, signlen);
			return(signlen);
		} else {
			MAEMOSEC_ERROR("signature buffer overflow (%d > %d)", signlen, maxlen);
			return(-ENOMEM);
		}
	}

	ssize_t 
	bb5_get_random(unsigned char *buf, size_t len)
	{
		int fd;
		ssize_t res = 0;

		fd = open("/dev/random", O_RDONLY);
		if (fd != -1) {
			res = read(fd, buf, len);
			if (res >= 0) {
				len -= res;
			} else
				MAEMOSEC_ERROR("cannot read /dev/random");
			close(fd);
		}
		// backup method
		while (len--) {
			*buf++ = rand() % 256;
			res++;
		}
		return(res);
	}


	ssize_t     
	bb5_rsakp_decrypt(int set, 
					  int key, 
					  const unsigned char *msg,
					  size_t len, 
					  unsigned char **plain) 
	{
		ssize_t res;
		RSA *rsakey = EVP_PKEY_get1_RSA(root_key);

		if (!rsakey) {
			MAEMOSEC_ERROR("No RSA key available");
			return(-1);
		}
		*plain = (unsigned char*) malloc(RSA_size(rsakey));
		if (!*plain) {
			MAEMOSEC_ERROR("cannot malloc");
			return(-1);
		}
		res = RSA_private_decrypt(len, msg, *plain, rsakey, RSA_PKCS1_PADDING);
		RSA_free(rsakey);
		return(res);
	}


} // extern "C"
