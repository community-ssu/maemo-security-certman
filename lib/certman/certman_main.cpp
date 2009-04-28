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

#include <maemosec_certman.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <regex.h>

// STL headers
#include <string>
#include <vector>
// #include <dequeue>
#include <stack>
#include <map>
using namespace std;

// OpenSSL headers
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>

// #include <libbb5.h>
#include <libbb5stub.h>
#include <maemosec_common.h>
#include <maemosec_storage.h>
using namespace maemosec;

#include "x509_container.h"

/*
 * Storage name prefix and directory names
 */

static const char cert_storage_prefix [] = "certman";
static const char common_cert_dir     [] = "/etc/certs";
static const char priv_cert_dir       [] = ".maemosec-certs";
static const char priv_keys_dir       [] = ".maemosec-keys";

/*
 * Directory access bits
 */

#define PUBLIC_DIR_MODE 0755
#define PRIVATE_DIR_MODE 0700


// TODO: should this really be a public
// EVP_PKEY *root_pkey = NULL;
static int is_inited = 0;


namespace maemosec 
{
    /**
	 * \brief A secure certificate container
	 */
	struct local_domain
	{
		storage* index;    ///< The secure storage containing the files
		string   dirname;  ///< The directory in which the actual files are
	};
}


static bool
verify_cert(X509_STORE* ctx, X509* cert, bool allow_unknown_issuer)
{
	X509_STORE_CTX *csc;
	bool retval;
	int rc;

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		MAEMOSEC_ERROR("cannot create new context");
		return(false);
	}

	rc = X509_STORE_CTX_init(csc, ctx, cert, NULL);
	if (rc == 0) {
		MAEMOSEC_ERROR("cannot initialize new context");
		return(false);
	}

	retval = (X509_verify_cert(csc) > 0);
	if (allow_unknown_issuer && 
		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY == csc->error)
		/*
		 * TODO: Make sure that this does not make openssl to ignore
		 * other, more severe errors.
		 */
		retval = 1;
	X509_STORE_CTX_free(csc);

	return(retval);
}


static bool
load_certs(vector<string> &certnames,
		   bool do_verify,
		   X509_STORE* certs
) {
	map<string, x509_container*> cert_map;
	stack<x509_container*> temp;
	int error, i = 0;

	// TODO: Is this logic necessary at all now that the 
	// certificates have been divided to domains? After all,
	// the tool should not force verification if that's not
	// what the user wants.

	// Load self signed certificates directly to X509 store
	// and put the rest into a map for quick access

	for (size_t i = 0; i < certnames.size(); i++) {

		x509_container* cert = new x509_container(certnames[i].c_str());

		if (0 < strlen(cert->key_id())) {
	        if (cert->is_self_signed()) 
			{
				MAEMOSEC_DEBUG(1, "self signed: %s", cert->subject_name());
				cert->m_verified = true;
				X509_STORE_add_cert(certs, cert->cert());
				delete(cert);

			} else {
				cert_map[cert->key_id()] = cert;
				MAEMOSEC_DEBUG(1, "%s\n\tkey    %s\n\tissuer %s", 
							   cert->subject_name(),
							   cert->key_id(), 
							   cert->issuer_key_id());
			}

		} else {
			MAEMOSEC_ERROR("Invalid certificate '%s'", cert->subject_name());
			delete(cert);
		}
	}

	/*
	 * Load and verify the rest of the certificates in the proper order
	 */
	for (map<string, x509_container*>::const_iterator ii = cert_map.begin();
		ii != cert_map.end();
		ii++) 
	{
		x509_container* cert = ii->second;
		x509_container* issuer;

		if (!cert) {
			MAEMOSEC_DEBUG(0, "What hell? (%s)", ii->first.c_str());
			continue;
		}
		MAEMOSEC_DEBUG(2, "iterate next (%d,%p,%d)", ++i, cert, cert->m_verified);

		/*
		 * Find possible issuer for those stupid certificates
		 * that didn't specify it by a x509v3 extension. If none
		 * is found, never mind as then the issuer must already
		 * be in the certs-store.
		 */
		if (0 == strlen(cert->issuer_key_id())) {
			bool found_issuer = false;
			MAEMOSEC_DEBUG(1, "Searching issuer for '%s'", cert->subject_name());
			for (map<string, x509_container*>::const_iterator jj = cert_map.begin();
				 jj != cert_map.end();
				 jj++) 
			{
				if (0 == strcmp(cert->issuer_name(), jj->second->subject_name())) {
					if (cert->is_issued_by(jj->second->cert(), &error)) {
						MAEMOSEC_DEBUG(1, "Found issuer");
						found_issuer = true;
						cert->set_issuer(jj->second);
						break;
					} else {
						MAEMOSEC_DEBUG(1, "Issuer names match but verification fails?");
					}
				} else {
					MAEMOSEC_DEBUG(5, "'%s' != '%s'",  cert->issuer_name(), jj->second->subject_name());
				}
			}
			if (!found_issuer)
				MAEMOSEC_DEBUG(1, "Issuer '%s' not found", cert->issuer_name());
		}

		if (!cert->m_verified) {
			temp.push(cert);

			/* 
			 * Verify issuers first, if any exist
			 */
			while (cert_map.count(cert->issuer_key_id())) {
				issuer = cert_map[cert->issuer_key_id()];
				if (issuer) {
					if (!issuer->m_verified) {
						MAEMOSEC_DEBUG(1, "push %s", issuer->issuer_key_id());
						temp.push(issuer);
					} else {
						MAEMOSEC_DEBUG(1, "issuer already verified");
						break;
					}
				} else {
					MAEMOSEC_ERROR("cannot find issuer %s for %s", 
						  cert->issuer_key_id(),
						  cert->subject_name()); 
					return(false);
				}
				cert = issuer;
			}

			while (temp.size()) {
				MAEMOSEC_DEBUG(2, "pop %d", temp.size());
				cert = temp.top();
				temp.pop();
				if (verify_cert(certs, cert->cert(), !do_verify)) {
					MAEMOSEC_DEBUG(2, "verified: %s", cert->subject_name());
					X509_STORE_add_cert(certs, cert->cert());
					cert->m_verified = true;
				} else {
					MAEMOSEC_ERROR("%s verification fails", cert->subject_name());
				}
			}
		} else
			MAEMOSEC_DEBUG(0, "Already verified");
	}
	MAEMOSEC_DEBUG(2, "erasing map");
	for (
		map<string, x509_container*>::const_iterator ii = cert_map.begin();
		ii != cert_map.end();
		ii++
	) {
		x509_container* cert = ii->second;
		delete(cert);
	}
	cert_map.clear();
	return(true);
}


static void
local_storage_dir(string& to_this, const char* subarea)
{
	string curbinname;

	/*
	 * TODO: This is an ugly patch to force root 
	 * processes to handle the same files as user
	 * processes.
	 */
	if (0 == getuid())
		to_this.assign("/home/user");
	else
		to_this.assign(GETENV("HOME",""));
	
	to_this.append(PATH_SEP);
	to_this.append(subarea);
	to_this.append(PATH_SEP);
#if 0
	process_name(curbinname);
	for (int i = 0; i < curbinname.length(); i++) {
		if (curbinname[i] == *PATH_SEP)
			curbinname[i] = '.';
	}
	to_this.append(curbinname);
#endif
	MAEMOSEC_DEBUG(1, "\nlocal cert dir = '%s'", to_this.c_str());
}


static void
decide_storage_name(const char* domain_name, int flags, string& dirname, string& storename)
{
	if (MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == flags) {
		// Make private name
		local_storage_dir(dirname, priv_cert_dir);
		storename.insert(0, ".");
		storename.insert(0, cert_storage_prefix);
		if (domain_name) {
			dirname.append(domain_name);
			storename.append(domain_name);
		}
		MAEMOSEC_DEBUG(1, "\ndirname  = %s\nstorename = %s", dirname.c_str(), storename.c_str());
	} else {
		storename.assign(domain_name);
		storename.insert(0, ".");
		storename.insert(0, cert_storage_prefix);
		dirname.assign(common_cert_dir);
		dirname.append(PATH_SEP);
		dirname.append(domain_name);
		MAEMOSEC_DEBUG(1, "\ndirname  = %s\nstorename = %s", dirname.c_str(), storename.c_str());
	}
}


static void
remove_spec_chars(char* in_string)
{
	char* to, *from = in_string;

	to = in_string;
	while (*from) {
		if (isalnum(*from) || strchr("_-", *from))
			*to++ = tolower(*from);
		from++;
	}
	*to = '\0';
}


/*
 * Make a unique filename for each certificate
 */
static void
make_unique_filename(X509* of_cert, const char* in_dir, string& to_string)
{
	const char* c;
	char nbuf[1024], *name;
	long serial;
	int rc;
	struct stat fs;

	to_string.assign(in_dir);
	to_string.append(PATH_SEP);
	maemosec_key_id key_id;
	if (0 == maemosec_certman_get_key_id(of_cert, key_id)) {
		append_hex(to_string, key_id, MAEMOSEC_KEY_ID_LEN);
		to_string.append(".pem");
	} else {
		MAEMOSEC_ERROR("Cannot get key id out of certificate");
		goto failed;
	}

  ok:
	MAEMOSEC_DEBUG(1, "=> %s", to_string.c_str());
	return;

  failed:
	;
}


static void
hex_to_key_id(const char* hstring, unsigned char* to_id)
{
	unsigned int val;

	memset(to_id, '\0', MAEMOSEC_KEY_ID_LEN);
	for (int i = 0; i < 2*MAEMOSEC_KEY_ID_LEN; i += 2) {
		if (0 == sscanf(hstring + i, "%02x", &val)) {
			MAEMOSEC_ERROR("invalid key file name '%s' at %d", hstring, i);
		}
		*to_id++ = (unsigned char) val;
	}
}


static X509*
load_cert_from_file(const char* from_file)
{
	FILE* fp;
	X509* cert;

	fp = fopen(from_file, "r");
	if (!fp) {
		fprintf(stderr, "Cannot read '%s' (%d)\n", from_file, errno);
		return(0);
	}
	cert = PEM_read_X509(fp, NULL, 0, NULL);
	if (!cert) {
		fprintf(stderr, "Cannot read certificate from '%s'\n", from_file);
	}
	fclose(fp);
	return(cert);
}


static int
store_key_to_file(maemosec_key_id key_id, EVP_PKEY* key, char* passwd)
{
	string storage_file_name;
	FILE* outfile;
	int rc;

	local_storage_dir(storage_file_name, priv_keys_dir);
	create_directory(storage_file_name.c_str(), PRIVATE_DIR_MODE);
	append_hex(storage_file_name, key_id, MAEMOSEC_KEY_ID_LEN);
	storage_file_name.append(".pem");

	outfile = fopen(storage_file_name.c_str(), "w");
	if (outfile) {
		chmod(storage_file_name.c_str(), S_IRUSR | S_IWUSR);
		rc = PEM_write_PKCS8PrivateKey(outfile, key, EVP_aes_256_ecb(), 
									   passwd, strlen(passwd), NULL, NULL);
		MAEMOSEC_DEBUG(1, "Stored key to '%s', rc = %d", 
					   storage_file_name.c_str(), rc);
		fclose(outfile);
		return(0);
	} else {
		MAEMOSEC_ERROR("Cannot open '%s' (%s)", storage_file_name.c_str(),
					   strerror(errno));
		return(errno);
	}
}


static int
return_pem_password(char* to_buf, int size, int rwflag, void* userdata)
{
	const char* password = (const char*) userdata;
	if (!password)
		return(-1);
	if (strlen(password) > size)
		return(-EINVAL);
	strcpy(to_buf, password);
	MAEMOSEC_DEBUG(1, "Returned password '%s'", password);
	return(strlen(password));
}


static int
read_key_from_file(maemosec_key_id key_id, EVP_PKEY** key, char* passwd)
{
	string storage_file_name;
	BIO* infile;
	X509_SIG *p8 = NULL;
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	int rc = 0;
	const char* lpasswd;

	if (passwd)
		lpasswd = passwd;
	else
		lpasswd = "";

	local_storage_dir(storage_file_name, priv_keys_dir);
	create_directory(storage_file_name.c_str(), PRIVATE_DIR_MODE);
	append_hex(storage_file_name, key_id, MAEMOSEC_KEY_ID_LEN);
	storage_file_name.append(".pem");

	MAEMOSEC_DEBUG(1, "Reading file '%s'", storage_file_name.c_str());

	infile = BIO_new_file(storage_file_name.c_str(), "rb");
	if (infile) {
		p8 = PEM_read_bio_PKCS8(infile, NULL, NULL, NULL);
		MAEMOSEC_DEBUG(1, "PEM_read_bio_PKCS8 ret %p", p8);
		if (p8) {
			MAEMOSEC_DEBUG(1, "Decrypting with '%s'", lpasswd);
			p8inf = (PKCS8_PRIV_KEY_INFO*)
				PKCS12_item_decrypt_d2i(p8->algor, 
										ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO),
										lpasswd, 
										strlen(lpasswd),
										p8->digest,
										1);
			MAEMOSEC_DEBUG(1, "PKCS8_decrypt ret %p", p8inf);
			X509_SIG_free(p8);
			if (p8inf) {
				*key = EVP_PKCS82PKEY(p8inf);
				if (*key) {
					MAEMOSEC_DEBUG(1, "Retrieved key from '%s'", 
								   storage_file_name.c_str());
					rc = 0;
				} else {
					MAEMOSEC_ERROR("Cannot retrieve key from '%s'", 
								   storage_file_name.c_str());
					rc = EINVAL;
				}
				PKCS8_PRIV_KEY_INFO_free(p8inf);
			} else 
				rc = EACCES;
		}
		BIO_free(infile);
		return(rc);
	} else {
		MAEMOSEC_ERROR("Cannot open '%s' (%s)", 
					   storage_file_name.c_str(),
					   strerror(errno));
		return(errno);
	}
}


static void
remove_key_file(maemosec_key_id key_id)
{
	string storage_file_name;
	int rc = 0;

	local_storage_dir(storage_file_name, priv_keys_dir);
	create_directory(storage_file_name.c_str(), PRIVATE_DIR_MODE);
	append_hex(storage_file_name, key_id, MAEMOSEC_KEY_ID_LEN);
	storage_file_name.append(".pem");

	if (file_exists(storage_file_name.c_str())) {
		rc = unlink(storage_file_name.c_str());
		MAEMOSEC_DEBUG(1, "Removed private key file '%s'", 
					   storage_file_name.c_str());
	}
}


static int
x509_equals(int pos, X509* cert, void* with_cert)
{
#if 1
	// The quick and easy method, but maybe not the right one
	return (X509_cmp(cert, (X509*)with_cert) == 0);
#else
	// The manual method, which involves dynamic allocation
	ASN1_BIT_STRING *lk, *rk;
	int res = 0;

	if (!cert || !with_cert)
		return(-EINVAL);
	lk = X509_get_pubkey(cert);
	rk = X509_get_pubkey((X509*)with_cert);
	if (lk && rk) {
		res = (EVP_PKEY_cmp(lk,rk) == 0);
	}
	if (lk)
		EVP_PKEY_free(lk);
	if (lk)
		EVP_PKEY_free(rk);
	if (res)
		// equals, terminate iteration
		return(pos);
	else
		return(0);
#endif
}


static void
maemosec_certman_int_init(void)
{
	string my_app_name;

	if (process_name(my_app_name)) {
		MAEMOSEC_DEBUG(1, "Init '%s'", my_app_name.c_str());
		is_inited = 1;
	} else
		MAEMOSEC_ERROR("Could not access process name");
}


static int
local_iterate_storage_names(storage::visibility_t of_visibility, 
							storage::protection_t of_protection, 
							const char* matching_names,
							maemosec_callback* cb_func,
							void* ctx)
{
	return(storage::iterate_storage_names(of_visibility, 
								 of_protection, 
								 matching_names,
								 cb_func, 
								 ctx));
}


// Visible part
extern "C" {

	struct cb_relay_par {
		void* o_ctx;
		maemosec_callback* cb_func;
	};


	int 
	maemosec_certman_open(X509_STORE** my_cert_store)
	{
		X509* bb5cert;

		maemosec_certman_int_init();
		bb5_init();
		if (my_cert_store)
			*my_cert_store = X509_STORE_new();
#if 0
		// This is really a el-gamal key or something like that
		// so don't store it
		bb5cert = bb5_get_cert(0);
		if (bb5cert)
			X509_STORE_add_cert(*my_cert_store, bb5cert);
#endif
		return(0);
	}

	/*
	 * Some libraries call these functions without initializing
	 * the library first. Use this ugly hack to help them work
	 * at the moment.
	 */

#define AUTOINIT do {							\
		if (!is_inited)							\
			maemosec_certman_open(NULL);		\
	} while (0)
	


	int maemosec_certman_collect(const char* domain, int shared, X509_STORE* my_cert_store)
	{
		vector<string> x;
		const char* sep, *start = domain;
		storage::visibility_t storvis;

		AUTOINIT;

		do {
			string domainname, dirname, storagename;
				
			sep = strchr(start, ':');
			if (sep) {
				domainname.assign(start, sep - start);
				start = sep + 1;
			} else
				domainname.assign(start);

			if (shared) {
				storvis = storage::vis_shared;
				decide_storage_name(domainname.c_str(), MAEMOSEC_CERTMAN_DOMAIN_SHARED, 
									dirname, storagename);
			} else {
				decide_storage_name(domainname.c_str(), MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, 
									dirname, storagename);
				storvis = storage::vis_private;
			}

			if (directory_exists(dirname.c_str())) {
				storage* store = new storage(storagename.c_str(),
											 storvis, 
											 storage::prot_signed);
				storage::stringlist certs;
				int pos;
				
				MAEMOSEC_DEBUG(1, "New store %p", store);
				pos = store->get_files(certs);
				MAEMOSEC_DEBUG(1, "Check %d certificates", pos);
				for (int i = 0; i < pos; i++) {
					if (store->verify_file(certs[i])) {
						MAEMOSEC_DEBUG(1, "Load '%s'", certs[i]);
						x.push_back(certs[i]);
					} else
						MAEMOSEC_ERROR("'%s' fails verification", certs[i]);
				}
				delete(store);
			} else {
				MAEMOSEC_ERROR("'%s' does not exists", storagename.c_str());
			}
		} while (sep);

		if (x.size()) {
			load_certs(x, true, my_cert_store);
		}
		return(0);
	}


	int
	maemosec_certman_close(X509_STORE* my_cert_store)
	{
		AUTOINIT;

		if (my_cert_store)
			X509_STORE_free(my_cert_store);
		bb5_finish();
		return(0);
	}


	int 
	maemosec_certman_open_domain(const char* domain_name, 
							 int flags, 
							 domain_handle* handle)
	{
		string storename;
		storage* certstore;
		struct local_domain mydomain;
		storage::visibility_t storvis;
		int rc;

		AUTOINIT;

		*handle = NULL;
		decide_storage_name(domain_name, flags, mydomain.dirname, storename);

		if (MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == flags) {
			rc = create_directory(mydomain.dirname.c_str(), PRIVATE_DIR_MODE);
			storvis = storage::vis_private;
		} else {
			rc = create_directory(mydomain.dirname.c_str(), PUBLIC_DIR_MODE);
			storvis = storage::vis_shared;
		}

		if (0 != rc) {
			return(rc);
		}
		mydomain.index = new storage(storename.c_str(), storvis, 
									 storage::prot_signed);
		if (mydomain.index) {
			*handle = new struct local_domain(mydomain);
			return(0);
		} else
			return(-1);
	}


	int 
	maemosec_certman_iterate_certs(
		domain_handle the_domain, 
		int cb_func(int,X509*,void*), 
		void* ctx)
	{
		storage::stringlist files;
		struct local_domain* mydomain;
		int i, pos, res = 0;

		AUTOINIT;

		if (!the_domain || !cb_func)
			return(-EINVAL);

		mydomain = (struct local_domain*)the_domain;
		pos = mydomain->index->get_files(files);
		MAEMOSEC_DEBUG(1, "%s: domain contains %d certificates", __func__, pos);
		for (i = 0; i < pos; i++) {
			X509* cert = load_cert_from_file(files[i]);
			if (cert) {
				res = cb_func(i, cert, ctx);
				MAEMOSEC_DEBUG(5, "callback returned %d", res);
				if (res != -1)
					X509_free(cert);
				else
					res = 0;
				if (res)
					break;
			} else
				return(-ENOENT);
		}
		return(res);
	}


	int maemosec_certman_load_cert(domain_handle the_domain, 
								   maemosec_key_id with_id, 
								   X509** cert)
	{
		
		string filename;
		struct local_domain *my_domain = (struct local_domain*)the_domain;

		AUTOINIT;

		filename = my_domain->dirname;
		filename.append(PATH_SEP);
		append_hex(filename, with_id, MAEMOSEC_KEY_ID_LEN);
		filename.append(".pem");
		MAEMOSEC_DEBUG(1, "Retrieve cert from '%s'", filename.c_str());
		// TODO: check integrity
		*cert = load_cert_from_file(filename.c_str());
		if (*cert)
			return(0);
		else
			return(ENOENT);
	}


	int
	maemosec_certman_nbrof_certs(domain_handle in_domain)
	{
		AUTOINIT;

		if (in_domain)
			return(((struct local_domain*)in_domain)->index->nbrof_files());
		else
			/*
			 * No domain, no certs
			 */
			return(0);
	}


	int 
	maemosec_certman_add_cert(domain_handle to_domain, X509* cert)
	{
		struct local_domain* mydomain = (struct local_domain*)to_domain;
		FILE* to_file;
		string filename;
		int pos, rc = 0;

		AUTOINIT;

		if (!to_domain || !cert)
			return(EINVAL);

#if 0
		pos = maemosec_certman_iterate_certs(to_domain, x509_equals, cert);
		if (0 != pos) {
			MAEMOSEC_DEBUG(0, 
						   "The certificate is already in the domain at %d", 
						   pos);
			return(EEXIST);
		}
#endif

		make_unique_filename(cert, mydomain->dirname.c_str(), filename);
		
		to_file = fopen(filename.c_str(), "w+");
		if (to_file) {
			if (PEM_write_X509(to_file, cert)) {
				MAEMOSEC_DEBUG(1, "written %s", filename.c_str());
			} else {
				MAEMOSEC_DEBUG(1, "cannot write to %s (%s)", filename.c_str(), 
					  strerror(errno));
				rc = errno;
			}
			fclose(to_file);
		} else
			rc = errno;

		if (0 == rc) {
			mydomain->index->add_file(filename.c_str());
			mydomain->index->commit();
		}
		return(rc);
	}

	int
	maemosec_certman_add_certs(domain_handle to_domain, 
							   char* cert_files[], 
							   unsigned count)
	{
		vector<string> certs;
		X509_STORE* tmp_store;
		X509_OBJECT* obj;
		int i, rc, added = 0;

		AUTOINIT;

		for (i = 0; i < count; i++) {
			if (cert_files[i]) {
				if (file_exists(cert_files[i])) {
					certs.push_back(cert_files[i]);
				} else
					MAEMOSEC_ERROR("Invalid certificate file '%s'", cert_files[i]);
			} else
				break;
		}
		tmp_store = X509_STORE_new();
		if (tmp_store) {
			if (load_certs(certs, false, tmp_store)) {
				for (i = 0; i < sk_X509_num(tmp_store->objs); i++) {
					obj = sk_X509_OBJECT_value(tmp_store->objs, i);
					if (X509_LU_X509 == obj->type) {
						rc = maemosec_certman_add_cert
							(to_domain, obj->data.x509);
						if (0 == rc)
							added++;
						else
							MAEMOSEC_ERROR("Failed to add a certificate");
					}
				}
			} else {
				MAEMOSEC_ERROR("Loading certificates failed");
			}
			X509_STORE_free(tmp_store);
		} else {
			MAEMOSEC_ERROR("Cannot create X509_STORE");
		}
		return(added);
	}


	int
	maemosec_certman_rm_cert(domain_handle from_domain, 
							 maemosec_key_id key_id)
	{
		int pos, rc;
		string filename;
		struct local_domain* mydomain = (struct local_domain*)from_domain;

		AUTOINIT;

		if (!mydomain)
			return(EINVAL);

		filename = mydomain->dirname;
		filename.append(PATH_SEP);
		append_hex(filename, key_id, MAEMOSEC_KEY_ID_LEN);
		filename.append(".pem");
		if (mydomain->index->contains_file(filename.c_str())) {
			MAEMOSEC_DEBUG(1, "Remove cert file '%s'", filename.c_str());
			mydomain->index->remove_file(filename.c_str());
			unlink(filename.c_str());
			/*
			 * TODO: Never remove keys in case it is used for another
			 * purpose. Must be fixed by checking other domains.
			 */
			// remove_key_file(key_id);
			mydomain->index->commit();
			return(0);
		} else
			return(ENOENT);
	}


	int 
	maemosec_certman_close_domain(domain_handle handle)
	{
		struct local_domain* mydomain;

		AUTOINIT;

		if (!handle)
			return(EINVAL);
		mydomain = (struct local_domain*)handle;
		delete(mydomain->index);
		delete(mydomain);
		return(0);
	}


	int 
	maemosec_certman_get_key_id(X509* of_cert, maemosec_key_id to_this)
	{
		AUTOINIT;

		if (!of_cert && !to_this)
			return(EINVAL);
		if (X509_pubkey_digest(of_cert, EVP_sha1(), to_this, NULL))
			return(0);
		else
			return(EINVAL);
	}

	/*
	 * Nickname is constructed by catenating these name components
	 * together in the order of precedence. -1 is a group separator.
	 */
	static const int nickname_components [] = {
		NID_commonName, -1, 
		NID_organizationalUnitName, NID_organizationName, NID_countryName, -1,
		NID_organizationalUnitName, NID_organizationName, -1,
		NID_organizationName, NID_countryName, -1,
		NID_organizationName, -1, 
		NID_organizationalUnitName, -1,
		-1
	};

	int
	maemosec_certman_get_nickname(X509* of_cert, 
								  char* to_buf, 
								  unsigned buf_len)
	{
		X509_NAME* name;
		bool found = false;
		int idx, npos = 0;
		string result;

		if (NULL == of_cert || NULL == to_buf || 0 == buf_len)
			return(EINVAL);

		name = X509_get_subject_name(of_cert);
		if (NULL == name)
			return(EINVAL);

		while (-1 != nickname_components[npos]) {
			idx = X509_NAME_get_index_by_NID(name, nickname_components[npos], -1);
			if (-1 == idx) {
				/*
				 * Component not found, roll forward
				 */
				result = "";
				while (-1 != nickname_components[npos])
					npos++;
			} else {
				X509_NAME_ENTRY *entry;
				ASN1_STRING *str = NULL;
				unsigned char *quark = NULL;

				entry = X509_NAME_get_entry(name, idx);
				if (NULL != entry)
					str = X509_NAME_ENTRY_get_data(entry);
				if (NULL != str)
					ASN1_STRING_to_UTF8(&quark, str);
				if (NULL != quark) {
					if ("" != result)
						result.append("/");
					result.append((char*)quark);
					OPENSSL_free(quark);
				}
			}
			npos++;
		}

		if (result.length() < buf_len)
			strcpy(to_buf, result.c_str());
		else {
			memcpy(to_buf, result.c_str(), buf_len);
			to_buf[buf_len] = '\0';
		}
		return(0);
	}


	int 
	maemosec_certman_store_key(maemosec_key_id with_id, 
							   EVP_PKEY* the_key, 
							   char* with_passwd)
	{
		AUTOINIT;

		return(store_key_to_file(with_id, the_key, with_passwd));
	}


	int
	maemosec_certman_retrieve_key(maemosec_key_id with_id, 
							   EVP_PKEY** the_key, 
							   char* with_passwd)
	{
		AUTOINIT;

		return(read_key_from_file(with_id, the_key, with_passwd));
	}


	static int
	cb_relay_key(int ord_nr, void* filename, void* ctx)
	{
		maemosec_key_id key_id;
		struct cb_relay_par *pars = (struct cb_relay_par*) ctx;
		hex_to_key_id((const char*)filename, key_id);
		return(pars->cb_func(ord_nr, key_id, pars->o_ctx));
	}


	int
	maemosec_certman_iterate_keys(maemosec_callback* cb_func, void* ctx)
	{
		string keystore_name;
		string name_expression;
		struct cb_relay_par relay_pars;

		AUTOINIT;

		name_expression = "^";
		for (int i = 0; i < MAEMOSEC_KEY_ID_LEN; i++)
			name_expression.append("[0-9a-f][0-9a-f]");
		name_expression.append("\\.pem$");
		local_storage_dir(keystore_name, priv_keys_dir);
		relay_pars.o_ctx = ctx;
		relay_pars.cb_func = cb_func;
		return(iterate_files(keystore_name.c_str(), 
							 name_expression.c_str(), 
							 cb_relay_key, 
							 &relay_pars));
	}


	static int
	cb_relay_storename(int ord_nr, void* filename, void* ctx)
	{
		struct cb_relay_par *pars = (struct cb_relay_par*) ctx;
		char* logical_name = (char*) filename;
		
		if (strlen(logical_name) > strlen(cert_storage_prefix))
			logical_name += strlen(cert_storage_prefix) + 1;
		return(pars->cb_func(ord_nr, logical_name, pars->o_ctx));
	}


	int
	maemosec_certman_iterate_domains(int flags,
									 maemosec_callback* cb_func,
									 void* ctx)
	{
		storage::visibility_t vis;
		string storage_names = cert_storage_prefix;
		struct cb_relay_par relay_pars;

		AUTOINIT;

		storage_names.assign(cert_storage_prefix);
		storage_names.append("\\..*");
		if (MAEMOSEC_CERTMAN_DOMAIN_SHARED == flags)
			vis = storage::vis_shared;
		else if (MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == flags)
			vis = storage::vis_private;
		else
			return(0 - EINVAL);
		relay_pars.o_ctx = ctx;
		relay_pars.cb_func = cb_func;
		MAEMOSEC_DEBUG(1, "Iterating storages '%s'", storage_names.c_str());
		return(local_iterate_storage_names(vis, 
										   storage::prot_signed, 
										   storage_names.c_str(), 
										   cb_relay_storename, 
										   &relay_pars));
	}

	int 
	maemosec_certman_key_id_to_str(maemosec_key_id key_id, 
								   char* to_buf, 
								   unsigned max_len)
	{
		unsigned i;
		char* start = to_buf;
		
		AUTOINIT;

		if (max_len < MAEMOSEC_KEY_ID_STR_LEN)
			return(EINVAL);

		for (i = 0; i < MAEMOSEC_KEY_ID_LEN; i++) {
			sprintf(to_buf, "%02hx", key_id[i]);
			to_buf += strlen(to_buf);
		}
		MAEMOSEC_DEBUG(1, "%s: %s", __func__, start);
		return(0);
	}


	int 
	maemosec_certman_str_to_key_id(char* from_str, 
								   maemosec_key_id key_id)
	{
		unsigned i = 0;
		unsigned short b;
		const char* f = from_str;

		AUTOINIT;

		if (!f)
			return(0);

		while (*f && sscanf(f, "%02hx", &b)) {
			f += 2;
			if (*f == ':')
				f++;
			key_id[i++] = (unsigned char)b;
			if (i == MAEMOSEC_KEY_ID_LEN)
				break;
		}
		
		if (i < MAEMOSEC_KEY_ID_LEN || *f) {
			return(EINVAL);
		} else
			return(0);
	}

	/*
	 * Debug
	 */
	int
	inspect_certificate(const char* pathname)
	{
		x509_container xc(pathname);
		return(0);
	}

} // extern "C"
