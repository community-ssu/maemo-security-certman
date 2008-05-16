/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

extern "C" {
#include <libcertman.h>
};

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

#include <libbb5.h>
#include <libbb5stub.h>
#include <sec_common.h>
#include <sec_storage.h>

#include "ngcm_x509_cert.h"

const string path_sep("/");
vector<string> cert_fn_exts;

// TODO: should this really be a public
EVP_PKEY *root_pkey = NULL;


static void
scan_dir_for_certs(const char* dirname, vector<string> &add_to)
{
	string abs_dirname;

	if (!strlen(dirname))
		return;

	if (!absolute_pathname(dirname, abs_dirname)) {
		ERROR("'%s' not a valid directory name", dirname);
		return;
	}
	
	DIR* hdir = opendir(abs_dirname.c_str());
	if (!hdir) {
		ERROR("cannot open dir '%s' (%d)", dirname, errno);
		return;
	}

	dirent* entry;

	while ((entry = readdir(hdir))) {
		char* extpos = strrchr(entry->d_name, '.');
		if (extpos) {
			string ext(extpos + 1);
			for (size_t i = 0; i < cert_fn_exts.size(); i++) {
				if (cert_fn_exts[i] == ext) {
					DEBUG(3, "'%s' is a certificate filename", entry->d_name);

					string cname(abs_dirname);
					cname.append(path_sep);
					cname.append(entry->d_name);
					add_to.push_back(cname);
					break;
				}
			}
		}
	}
	closedir(hdir);

}


static bool
verify_cert(X509_STORE* ctx, X509* cert)
{
	X509_STORE_CTX *csc;
	bool retval;
	int rc;

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		ERROR("cannot create new context");
		print_openssl_errors();
		return(false);
	}

	rc = X509_STORE_CTX_init(csc, ctx, cert, NULL);
	if (rc == 0) {
		ERROR("cannot initialize new context");
		print_openssl_errors();
		return(false);
	}

	retval = (X509_verify_cert(csc) > 0);
	X509_STORE_CTX_free(csc);

	return(retval);
}


static bool
load_certs(vector<string> &certnames,
		   X509_STORE* certs
) {
	map<string, ngcm_x509_cert*> cert_map;
	stack<ngcm_x509_cert*> temp;

	// Load self signed certificates directly to X509 store
	// and put the rest into a map for quick access

	for (size_t i = 0; i < certnames.size(); i++) {
		ngcm_x509_cert* cert = new ngcm_x509_cert(certnames[i].c_str());

		if (strcmp(cert->key_id(), cert->issuer_key_id()) == 0
			|| strlen(cert->issuer_key_id()) == 0) 
		{
			DEBUG(1, "self signed: %s", cert->subject_name());
			cert->m_verified = true;
			X509_STORE_add_cert(certs, cert->cert());

		} else {
			cert_map[cert->key_id()] = cert;
			DEBUG(1, "%s\n\tkey    %s\n\tissuer %s", 
				  cert->subject_name(),
				  cert->key_id(), 
				  cert->issuer_key_id());
		}
	}

	// Load and verify the rest of the certificates in the proper order
	for (
		map<string, ngcm_x509_cert*>::const_iterator ii = cert_map.begin();
		ii != cert_map.end();
		ii++
	) {
		ngcm_x509_cert* cert = ii->second;
		ngcm_x509_cert* issuer;

		DEBUG(2, "iterate next (%p,%d)", cert, cert->m_verified);

		if (!cert) {
			DEBUG(0, "What hell? (%s)", ii->first.c_str());
			continue;
		}

		if (!cert->m_verified) {
			temp.push(cert);
			while (cert_map.count(cert->issuer_key_id())) {
				issuer = cert_map[cert->issuer_key_id()];
				if (issuer) {
					if (!issuer->m_verified)
						temp.push(issuer);
					else
						break;
				} else
					ERROR("cannot find issuer %s for %s", 
						  cert->issuer_key_id(),
						  cert->subject_name()); 
				cert = issuer;
			}

			while (temp.size()) {
				DEBUG(2, "pop %d", temp.size());
				cert = temp.top();
				temp.pop();
				if (verify_cert(certs, cert->cert())) {
					DEBUG(2, "verified: %s", cert->subject_name());
					X509_STORE_add_cert(certs, cert->cert());
					cert->m_verified = true;
				} else {
					ERROR("%s verification fails", cert->subject_name());
				}
			}
		}
	}
	DEBUG(2, "erasing map");
	for (
		map<string, ngcm_x509_cert*>::const_iterator ii = cert_map.begin();
		ii != cert_map.end();
		ii++
	) {
		ngcm_x509_cert* cert = ii->second;
		delete(cert);
	}
	cert_map.clear();
	return(true);
}

// Some initialization with hard-coded constants.
// Some of these should maybe be moved to a config
// file...

static const char cert_dir_name [] = "/etc/certs";


// Visible part
extern "C" {

	int 
	ngcm_open(X509_STORE** my_cert_store)
	{
		// OpenSSL initialization.
		CRYPTO_malloc_init();
		// OPENSSL_config(NULL);
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		*my_cert_store = X509_STORE_new();
		X509_STORE_add_cert(*my_cert_store, bb5_get_cert());
		return(0);
	}

	int ngcm_collect(const char* domain, X509_STORE* my_cert_store)
	{
		string dirname;
		vector<string> x;

		dirname = cert_dir_name;
		dirname.append("/");
		dirname.append(domain);

		// Recognized cert file extensions
		cert_fn_exts.push_back(string("crt"));
		cert_fn_exts.push_back(string("pem"));

		scan_dir_for_certs(dirname.c_str(), x);

		if (x.size()) {
			for (size_t i = 0; i < x.size(); i++)
				DEBUG(1, "Seen: %s", x[i].c_str());

			load_certs(x, my_cert_store);
		}
		return(0);
	}

	int
	ngcm_close(X509_STORE* my_cert_store)
	{
		X509_STORE_free(my_cert_store);
		RAND_cleanup();
		EVP_cleanup();
		X509_TRUST_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();
		return(0);
	}
} // extern "C"

#if 0
// Some dead code saved as a reference for a while
enum cmd_type {cmd_sign, cmd_verify, cmd_none} cmd = cmd_none;

static const char* x509_obj_names[] = {
	"fail", "x509", "crl", "pkey"
};

int 
main(int argc, char* argv[])
{
	vector<string> certnames;
	X509* root_crt = NULL;
	EVP_PKEY *root_pkey = NULL;
	X509_LOOKUP *lookup = NULL;
	ngcm_x509_cert* cert = NULL;
	int rc;
	char a;

	// OpenSSL initialization.
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	// Initializations
	ngcm_certificates = X509_STORE_new();
	if (ngcm_certificates == NULL) {
		ERROR("cannot create X509 store");
		print_openssl_errors();
		goto end;
	}

	// Is this really necessary?
	// apps_startup();

	lookup = X509_STORE_add_lookup(ngcm_certificates,X509_LOOKUP_file());
	if (lookup == NULL) {
		ERROR("cannot add lookup");
		print_openssl_errors();
		goto end;
	}

	// Recognized cert file extensions
	cert_fn_exts.push_back(string("crt"));
	cert_fn_exts.push_back(string("pem"));

    while (1) {
		a = getopt(argc, argv, "v:k:t:d:s:h");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
		case 'd':
			scan_dir_for_ngcm_certificates(optarg, certnames);
			break;

		case 'k':
			// openssl/apps/apps.c::load_key is not public?
			// this code borrowed from there
		{
			BIO* keyfile = NULL;

			keyfile = BIO_new(BIO_s_file());

			if (!keyfile) {
				ERROR("cannot create BIO");
				goto end;
			}

			// TODO: there are many different formats for keys
			if (BIO_read_filename(keyfile, optarg) <= 0) {
				ERROR("cannot load root CA key from '%s'", optarg);
				print_openssl_errors();
				goto end;
			}

			// TODO: this may be password protected. It's a demo feature
			// anyway, in reality the BB5 functions should be used for 
            // private key purposes.
			root_pkey = PEM_read_bio_PrivateKey(keyfile, NULL, NULL, NULL);
			if (!root_pkey) {
				DEBUG(1, "Not an PEM file\n");
			}

			BIO_free(keyfile);
			break;
		}

		case 't':
			// TODO: the trusted root certificate(s) should be loaded
			// from BB5
			rc = X509_LOOKUP_load_file(lookup, optarg, X509_FILETYPE_PEM);
			if (rc == 0) {
				ERROR("cannot load root CA from '%s'", optarg);
				print_openssl_errors();
				goto end;
			}
			break;

		case 's':
			// A certificate to be signed
			cert = new ngcm_x509_cert(optarg);
			if (!cert->cert()) {
				delete(cert);
				cert = NULL;
				goto end;
			}
			cmd = cmd_sign;
			break;

		case 'v':
			// A certificate to be verified
			cert = new ngcm_x509_cert(optarg);
			if (!cert->cert()) {
				delete(cert);
				cert = NULL;
				goto end;
			}
			cmd = cmd_verify;
			break;

		case 'D':
			debug_level++;
			break;

		default:
			show_usage();
			return(1);
		}
	}

	if (certnames.size() > 0) {
		if (!load_ngcm_certificates(certnames, ngcm_certificates)) {
			ERROR("cannot load certificates. Exit!");
			goto end;
		}
		// show_ngcm_certificates(ngcm_certificates);
	}

	if (!cert || !cert->cert()) {
		goto end;
	}

	switch (cmd) 
	{
	case cmd_sign: {
		if (!root_pkey || !root_crt) {
			ERROR("cannot sign without the private key");
			goto end;
		}

		const EVP_MD* digest;
		X509* sign_cert = cert->cert();

		digest=EVP_sha1();
#if 0
		if (root_pkey->type == EVP_PKEY_DSA)
			digest=EVP_dss1();
		else if (root_pkey->type == EVP_PKEY_EC)
			digest=EVP_ecdsa();
#endif

		X509_set_issuer_name(sign_cert,X509_get_subject_name(root_crt));
		if (X509_sign(sign_cert, root_pkey, digest)) {
			DEBUG(1, "Signed OK");
			cert->print();
		} else {
			ERROR("Cannot sign");
			print_openssl_errors();
		}
		break;
	}

	case cmd_verify:
		if (verify_cert(ngcm_certificates, cert->cert())) {
			printf("Verify OK\n");
		} else {
			printf("Verification failed\n");
			print_openssl_errors();
		}
		break;

	default:
		break;
	}

end:
	if (cert)
		delete(cert);
	X509_STORE_free(ngcm_certificates);
	RAND_cleanup();
	EVP_cleanup();
	X509_TRUST_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();

    return(0);
}
#endif
