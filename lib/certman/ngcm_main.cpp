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

// #include <libbb5.h>
#include <libbb5stub.h>
#include <sec_common.h>
#include <sec_storage.h>
using namespace ngsw_sec;

#include "ngcm_x509_cert.h"

// Some initialization with hard-coded constants.
// Some of these should maybe be moved to a config
// file...

static const char cert_dir_name [] = "/etc/certs";
static const char priv_dir_name [] = ".certs";

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


#define SVAL(s) (s?s:"")


// The local certificate repository is application specific, and created
// in a dirman ectory that contains the command-line
static void
local_cert_dir(string& to_this, string& storename)
{
	string curbinname;

	to_this.assign(SVAL(getenv("HOME")));
	to_this.append(path_sep);
	to_this.append(priv_dir_name);
	to_this.append(path_sep);
	absolute_pathname(SVAL(getenv("_")), curbinname);
	for (int i = 0; i < curbinname.length(); i++) {
		if (curbinname[i] == path_sep[0])
			curbinname[i] = '.';
	}
	to_this.append(curbinname);
	storename.assign(SVAL(getenv("USER")));
	storename.append(curbinname);
	DEBUG(1, "\nlocal cert dir = '%s'\nprivate store name = '%s'", 
		  to_this.c_str(), storename.c_str());
}


static int
create_if_needed(const char* dir)
{
	struct stat fs;
	int rc;
	
	DEBUG(2, "Test '%s'", dir);
	rc = stat(dir, &fs);
	if (-1 == rc) {
		if (errno == ENOENT) {
			DEBUG(2, "Create '%s'", dir);
			rc = mkdir(dir, 0700);
			if (-1 != rc) {
				return(0);
			} else {
				DEBUG(2, "Creation failed (%s)", strerror(rc));
				return(errno);
			}
		} else {
			DEBUG(2, "Error other than ENOENT with '%s' (%s)", 
				  dir, strerror(rc));
			return(errno);
		}
	} else {
		if (!S_ISDIR(fs.st_mode)) {
			DEBUG(2, "overlapping non-directory");
			return(EEXIST);
		} else
			return(0);
	}
}


static int
create_private_directory(const char* dir)
{
	string locbuf;
	char* sep;
	struct stat fs;
	int rc;

	if (!dir)
		return(EINVAL);

	locbuf.assign(dir);
	sep = (char*)locbuf.c_str();
	sep++;
	
	while (sep && *sep) {
		sep = strchr(sep, path_sep[0]);
		if (sep) {
			*sep = '\0';
			rc = create_if_needed(locbuf.c_str());
			if (0 != rc) {
				return(rc);
			}
			*sep = path_sep[0];
			sep++;
		}
	}
	rc = create_if_needed(dir);
	return(rc);
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


static void
make_unique_filename(
					 const char* of_string, 
					 const char* with_ext, 
					 const char* out_dir, 
					 char* to_buf, 
					 int maxlen
) {
	const char* c;
	char* to;
	char* temp = (char*)malloc(maxlen + 1);
	int i, rc;
	struct stat fs;

	*to_buf = '\0';
	if (!of_string) {
		ERROR("certificate has no name");
		return;
	}

	DEBUG(0,"Mangling name '%s'\n", of_string);

	if (!temp) {
		fprintf(stderr, "cannot allocate (%d)\n", errno);
		return;
	}
	to = temp;
	if (out_dir && strlen(out_dir)) {
		strncpy(to, out_dir, maxlen);
		to[maxlen-1] = '\0';
		to += strlen(to);
	} else {
		strcpy(to, "./");
		to += 2;
	}
	if (*(to - 1) != '/') {
		*to++ = '/';
	}

	maxlen -= (to - temp);
	/* room for ".99.ext" */
	maxlen -= strlen(with_ext) + 4;

	c = strstr(of_string, "O=");
	if (c) 
		c += 2;
	else
		c = of_string;

	while (*c && (strchr("/,=",*c) == NULL))
	{
		if (maxlen) {
			if (!isalnum(*c))
				*to = '_';
			else
				*to = *c;
			to++;
			maxlen--;
		} else
			break;
		c++;
	}

	*to = '\0';
	for (i = 1; i < 100; i++) {
		sprintf(to, ".%d.%s", i, with_ext);
		rc = stat(temp, &fs);
		if (rc == -1)
			break;
	}

	if (rc == -1) {
		strcpy(to_buf, temp);
	} else {
		fprintf(stderr, "Too many files '%s' (%d)\n", temp, errno);
		strcpy(to_buf, "");
	}
	free(temp);
}


typedef struct local_domain
{
	storage* index;
	string   dirname;
};


// Visible part
extern "C" {

	int 
	ngsw_certman_open(X509_STORE** my_cert_store)
	{
		bb5_init();
		*my_cert_store = X509_STORE_new();
		X509_STORE_add_cert(*my_cert_store, bb5_get_cert());
		return(0);
	}

	int ngsw_certman_collect(const char* domain, X509_STORE* my_cert_store)
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
	ngsw_certman_close(X509_STORE* my_cert_store)
	{
		X509_STORE_free(my_cert_store);
		bb5_finish();
		return(0);
	}

	int 
	ngsw_cert_is_valid(X509_STORE* my_cert_store, X509* cert)
	{
		return(0);
	}


	int 
	ngsw_certman_create_domain(const char* name_domain, int flags)
	{
		string dirname, storename;
		storage* certstore;
		int rc;

		local_cert_dir(dirname, storename);
		DEBUG(1, "\ndirname  = %s\nstorename = %s", dirname.c_str(), storename.c_str());
		rc = create_private_directory(dirname.c_str());
		if (0 != rc)
			return(rc);

		certstore = new storage(storename.c_str(), storage::prot_sign);
		if (certstore) {
			certstore->commit();
			delete(certstore);
			return(0);
		} else
			return(-1);
	}


	int 
	ngsw_certman_open_domain(const char* name_domain, int* handle)
	{
		string dirname, storename;
		storage* certstore;
		struct local_domain mydomain;
		int rc;

		*handle = 0;
		local_cert_dir(mydomain.dirname, storename);

		DEBUG(1, "\ndirname  = %s\nstorename = %s", 
			  mydomain.dirname.c_str(), 
			  storename.c_str());

		mydomain.index = new storage(storename.c_str());
		if (mydomain.index) {
			*handle = (int) new struct local_domain(mydomain);
			return(0);
		} else
			return(-1);
	}

	int 
	ngsw_certman_iterate_domain(int the_domain, int cb_func(int,X509*))
	{
		cb_func(0,NULL);
		return(-1);
	}

	int 
	ngsw_certman_add_cert(int to_domain, X509* cert)
	{
		// TODO: Check that the certificate does not exist in 
		// the store already
		struct local_domain* mydomain = (struct local_domain*)to_domain;
		char buf[255], *name;
		FILE* to_file;
		int rc = 0;

		if (!to_domain || !cert)
			return(EINVAL);
		
		name = X509_NAME_oneline(X509_get_subject_name(cert),
								 buf, 
								 sizeof(buf));

		make_unique_filename(name, "pem", mydomain->dirname.c_str(), buf, sizeof(buf));
		
		to_file = fopen(buf, "w+");
		if (to_file) {
			if (PEM_write_X509(to_file, cert)) {
				DEBUG(0, "written %s", buf);
			} else {
				DEBUG(1, "cannot write to %s (%s)", buf, strerror(errno));
				rc = errno;
			}
			fclose(to_file);
		} else
			rc = errno;

		if (0 == rc) {
			mydomain->index->add_file(buf);
			mydomain->index->commit();
		}
		return(rc);
	}

	int
	ngsw_certman_rm_cert(int to_domain, X509* cert)
	{
		return(-1);
	}

	int 
	ngsw_certman_close_domain(int handle)
	{
		return(-1);
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
