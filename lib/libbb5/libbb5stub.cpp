/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include <sys/time.h>

extern "C" {
#include "libbb5stub.h"
}

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "sec_common.h"

static const char root_crt_name [] = "/etc/certs/trusted/root.ca";
static const char root_key_name [] = "/etc/certs/trusted/root.key";

static X509*     root_crt = NULL;
static EVP_PKEY* root_key = NULL;


static void
load_root_certificate(X509_STORE* to_this)
{
	X509_LOOKUP *lookup = NULL;
	int rc;
	
	lookup = X509_STORE_add_lookup(to_this, X509_LOOKUP_file());
	if (lookup == NULL) {
		ERROR("cannot add lookup");
		print_openssl_errors();
		goto end;
	}
		
	rc = X509_LOOKUP_load_file(
		lookup, 
		root_crt_name,
		X509_FILETYPE_PEM);

	if (rc == 0) {
		DEBUG(1, "cannot load root certificate from '%s'", root_crt_name);
	} else {
		X509_OBJECT* obj;
		DEBUG(1, "loaded root ca from '%s'", root_crt_name);
		obj = sk_X509_OBJECT_value(to_this->objs, 0);
		if (obj && obj->type == X509_LU_X509)
			root_crt = obj->data.x509;
		else
			ERROR("cannot find root certificate");
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
		ERROR("cannot create BIO");
		return;
	}
	
	// TODO: there are many different formats for keys
	if (BIO_read_filename(keyfile, root_key_name) <= 0) {
		ERROR("cannot load root CA key from '%s'", root_key_name);
		print_openssl_errors();
		return;
	}
	root_key = PEM_read_bio_PrivateKey(keyfile, NULL, NULL, NULL);
	if (!root_key) {
		ERROR("Cannot load private key from '%s'", root_key_name);
	} else
		DEBUG(1, "loaded root key from '%s'", root_key_name);
	BIO_free(keyfile);
}

extern "C" {

	X509_STORE*
	bb5_init(void)
	{
		X509_STORE* cstore;
		struct timeval now;

		cstore = X509_STORE_new();
		if (cstore == NULL) {
			ERROR("cannot create X509 store");
			print_openssl_errors();
			return(NULL);
		}
		load_root_certificate(cstore);
		load_root_key();

		gettimeofday(&now, NULL);
		srand(now.tv_usec);
		return(cstore);
	}


	void
	bb5_finish(void)
	{
		if (root_key)
			EVP_PKEY_free(root_key);
	}


	X509*
	bb5_get_cert(void)
	{
		return(root_crt);
	}


	int
	bb5_rsakp_sign(EVP_MD_CTX* ctx, unsigned char* md, size_t maxlen)
	{
		int rc;
		unsigned int signlen = 0;
		unsigned char lmd[1024];

		if (!root_key) {
			ERROR("cannot sign: no private key");
			return(0);
		}
		
		rc = EVP_SignFinal(ctx, lmd, &signlen, root_key);
		if (rc != 1) {
			ERROR("signing failed");
			print_openssl_errors();
			return(0);
		}
		if (signlen <= maxlen) {
			memcpy(md, lmd, signlen);
			return(signlen);
		} else {
			ERROR("signature buffer overflow (%d > %d)", signlen, maxlen);
			return(-ENOMEM);
		}
	}

	ssize_t 
	bb5_get_random(unsigned char *buf, size_t len)
	{
		ssize_t res = 0;
		while (len--) {
			*buf++ = rand() % 256;
			res++;
		}
		return(res);
	}

} // extern "C"


