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

static const char cert_storage_prefix [] = "ngswcertman.";
static const char cert_dir_name       [] = "/etc/certs";
static const char priv_dir_name       [] = ".certs";

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

	// TODO: Is this logic necessary at all now that the 
	// certificates have been divided to domains? After all,
	// the tool should not force verification if that's not
	// what the user wants.

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
			delete(cert);
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
create_if_needed(const char* dir, int mode)
{
	struct stat fs;
	int rc;
	
	DEBUG(2, "Test '%s'", dir);
	rc = stat(dir, &fs);
	if (-1 == rc) {
		if (errno == ENOENT) {
			DEBUG(2, "Create '%s'", dir);
			rc = mkdir(dir, mode);
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
create_private_directory(const char* dir, int mode)
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
			rc = create_if_needed(locbuf.c_str(), mode);
			if (0 != rc) {
				return(rc);
			}
			*sep = path_sep[0];
			sep++;
		}
	}
	rc = create_if_needed(dir, mode);
	return(rc);
}


static void
decide_storage_name(const char* domain_name, int flags, string& dirname, string& storename)
{
	if (NGSW_CD_PRIVATE == flags) {
		// Make private name
		local_cert_dir(dirname, storename);
		storename.insert(0, cert_storage_prefix);
		if (domain_name) {
			dirname.append(path_sep);
			dirname.append(domain_name);
			storename.append(".");
			storename.append(domain_name);
		}
		DEBUG(1, "\ndirname  = %s\nstorename = %s", dirname.c_str(), storename.c_str());
	} else {
		storename.assign(domain_name);
		storename.insert(0, cert_storage_prefix);
		dirname.assign(cert_dir_name);
		dirname.append(path_sep);
		dirname.append(domain_name);
		DEBUG(1, "\ndirname  = %s\nstorename = %s", dirname.c_str(), storename.c_str());
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
 * Form a filename out of certificate's subject name and serial number
 * TODO: This might not be the right thing to do, 
 */
static void
make_unique_filename(X509* of_cert, const char* in_dir, string& to_string)
{
	const char* c;
	char nbuf[1024], *name;
	long serial;
	int rc;
	struct stat fs;

	to_string.assign("");

	name = X509_NAME_oneline(X509_get_subject_name(of_cert), nbuf, sizeof(nbuf));
	serial = ASN1_INTEGER_get(X509_get_serialNumber(of_cert));

	if (!name) {
		ERROR("Cert has no name!!!");
		return;
	}

	DEBUG(1,"Making filename out of '%s'\n+ in dir '%s'", name, in_dir);

	to_string.assign(in_dir);
	to_string.append(path_sep);

	// Use the organization name from subject name as basis
	c = strstr(name, "O=");
	if (c) 
		c += 2;
	else
		c = name;

	while (*c && (strchr("/,=",*c) == NULL))
	{
		if (!isalnum(*c))
			to_string.append(1,'_');
		else
			to_string.append(1,*c);
		c++;
	}
	
	// Do not use the real serial number
	serial = 1;
	do {
		sprintf(nbuf, "%s.%ld.pem", to_string.c_str(), serial);
		rc = stat(nbuf, &fs);
		if (-1 == rc) {
			if (ENOENT == errno)
				break;
			else {
				ERROR("cannot do stat on '%s' (%s)", nbuf, strerror(errno));
				return;
			}
		} else
			serial++;
	} while (serial < LONG_MAX);

  ok:
	to_string.assign(nbuf);
	DEBUG(1, "=> %s", to_string.c_str());
	return;

  failed:
	;
}


typedef struct local_domain
{
	storage* index;
	string   dirname;
};


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
		return(EINVAL);
	lk = X509_get_pubkey(cert);
	rk = X509_get_pubkey((X509*)with_cert);
	if (lk && rk) {
		res = (EVP_PKEY_cmp(lk,rk) == 0);
	}
	if (lk)
		EVP_PKEY_free(lk);
	if (lk)
		EVP_PKEY_free(rk);
	return(res);
#endif
}


// Visible part
extern "C" {

	int 
	ngsw_certman_open(X509_STORE** my_cert_store)
	{
		X509* bb5cert;

		bb5_init();
		*my_cert_store = X509_STORE_new();
		bb5cert = bb5_get_cert(0);
		if (bb5cert)
			X509_STORE_add_cert(*my_cert_store, bb5cert);
		return(0);
	}

	int ngsw_certman_collect(const char* domain, X509_STORE* my_cert_store)
	{
		vector<string> x;
		const char* sep, *start = domain;

		do {
			string domainname, dirname, storagename;
				
			sep = strchr(start, ':');
			if (sep) {
				domainname.assign(start, sep - start);
				start = sep + 1;
			} else
				domainname.assign(start);

			// TODO: This is an ugly hack: always try common name first,
			// then private if the common storage does not exist
			decide_storage_name(domainname.c_str(), NGSW_CD_COMMON, 
								dirname, storagename);
			if (!directory_exists(dirname.c_str()))
				decide_storage_name(domainname.c_str(), NGSW_CD_PRIVATE, 
									dirname, storagename);

			if (directory_exists(dirname.c_str())) {
				storage* store = new storage(storagename.c_str());
				storage::stringlist certs;
				int pos = store->get_files(certs);

				for (int i = 0; i < pos; i++) {
					if (store->verify_file(certs[i])) {
						DEBUG(1, "Load '%s'", certs[i]);
						x.push_back(certs[i]);
					} else
						ERROR("'%s' fails verification");
				}
				delete(store);
			} else {
				ERROR("'%s' does not exists", storagename.c_str());
			}
		} while (sep);

		if (x.size()) {
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

	// TODO: return issuer index/cert
	int 
	ngsw_cert_is_valid(X509_STORE* my_cert_store, X509* cert)
	{
		X509_STORE_CTX *csc;
		int retval;
		int rc;

		csc = X509_STORE_CTX_new();
		if (csc == NULL) {
			ERROR("cannot create new context");
			return(0);
		}

		rc = X509_STORE_CTX_init(csc, my_cert_store, cert, NULL);
		if (rc == 0) {
			ERROR("cannot initialize new context");
			return(0);
		}

		retval = (X509_verify_cert(csc) > 0);
		X509_STORE_CTX_free(csc);

		return(retval);
	}


	int 
	ngsw_certman_open_domain(const char* domain_name, int flags, int* handle)
	{
		string storename;
		storage* certstore;
		struct local_domain mydomain;
		int rc;

		*handle = -1;
		decide_storage_name(domain_name, flags, mydomain.dirname, storename);
		// TODO: directory access bits are plain numbers here
		// ugly, ugly...
		if (NGSW_CD_PRIVATE == flags) {
			rc = create_private_directory(mydomain.dirname.c_str(), 0700);
		} else {
			rc = create_private_directory(mydomain.dirname.c_str(), 0755);
		}
		if (0 != rc) {
			return(rc);
		}
		mydomain.index = new storage(storename.c_str(), storage::prot_sign);
		if (mydomain.index) {
			*handle = (int) new struct local_domain(mydomain);
			return(0);
		} else
			return(-1);
	}

	int 
	ngsw_certman_iterate_domain(int the_domain, int cb_func(int,X509*,void*), void* ctx)
	{
		storage::stringlist files;
		struct local_domain* mydomain;
		int i, pos, res = 0;

		if (!the_domain || !cb_func)
			return(-EINVAL);

		mydomain = (struct local_domain*)the_domain;
		pos = mydomain->index->get_files(files);
		DEBUG(1, "domain contains %d certificates", pos);
		for (i = 0; i < pos; i++) {
			X509* cert = load_cert_from_file(files[i]);
			DEBUG(1, "%d: %p", i, cert);
			if (cert) {
				res = cb_func(i, cert, ctx);
				X509_free(cert);
				if (res)
					break;
			} else
				return(-ENOENT);
		}
		return(i);
	}

	int
	ngsw_certman_nbrof_certs(int in_domain)
	{
		if (in_domain)
			return(((struct local_domain*)in_domain)->index->nbrof_files());
		else
			return(-1);
	}

	int 
	ngsw_certman_add_cert(int to_domain, X509* cert)
	{
		struct local_domain* mydomain = (struct local_domain*)to_domain;
		FILE* to_file;
		string filename;
		int pos, rc = 0;

		if (!to_domain || !cert)
			return(EINVAL);

		pos = ngsw_certman_iterate_domain(to_domain, x509_equals, cert);
		if (pos < ngsw_certman_nbrof_certs(to_domain)) {
			DEBUG(0,"The certificate is already in the domain");
			return(EEXIST);
		}

		make_unique_filename(cert, mydomain->dirname.c_str(), filename);
		
		to_file = fopen(filename.c_str(), "w+");
		if (to_file) {
			if (PEM_write_X509(to_file, cert)) {
				DEBUG(1, "written %s", filename.c_str());
			} else {
				DEBUG(1, "cannot write to %s (%s)", filename.c_str(), 
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
	ngsw_certman_rm_cert(int to_domain, int pos)
	{
		int count, rc;
		storage::stringlist certs;
		struct local_domain* mydomain = (struct local_domain*)to_domain;

		if (!to_domain)
			return(EINVAL);
		count = mydomain->index->get_files(certs);
		if (pos < 0 || pos >= count)
			return(EINVAL);
		mydomain->index->remove_file(certs[pos]);
		mydomain->index->commit();
		return(0);
	}

	int 
	ngsw_certman_close_domain(int handle)
	{
		struct local_domain* mydomain;

		if (!handle)
			return(EINVAL);
		mydomain = (struct local_domain*)handle;
		delete(mydomain->index);
		delete(mydomain);
	}
} // extern "C"
