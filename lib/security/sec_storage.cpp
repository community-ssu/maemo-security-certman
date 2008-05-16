/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include "sec_storage.h"
using namespace secure;

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "sec_common.h"
#include "libbb5stub.h"

extern "C" {

#define DIGESTTYP EVP_sha1
#define DIGESTLEN EVP_MD_size(DIGESTTYP())
#define EVPOK 1

static const char sec_root[] = "/secure";
// static X509_STORE* certs = NULL;
static int ccount = 0;

#define signature_mark "SIGNATURE:"

static unsigned char
hex2bin(char* hex2str)
{
	unsigned char res;

	res  = *hex2str <= '9' ? *hex2str - '0' : 10 + *hex2str - 'a';
	res *= 0x10;
	hex2str++;
	res += *hex2str <= '9' ? *hex2str - '0' : 10 + *hex2str - 'a';
	return(res);
}


storage::storage(const char* name, protection_t protect) 
{
	char* end, *c = NULL;
	unsigned char* data = NULL;
	string filename;
	int fd = -1, rc;
	ssize_t len;
	EVP_MD_CTX vfctx;

	m_name = name;

	if (ccount == 0) {
		// certs = bb5_init();
		bb5_init();
	}
	ccount++;
	if (bb5_get_cert() == NULL) {
		ERROR("Initialization error");
		return;
	}

	filename = sec_root;
	filename.append("/");
	filename.append(name);

	data = map_file(filename.c_str(), &fd, &len);
	if (data == MAP_FAILED) {
		DEBUG(1, "'%s' does not exist, created", filename.c_str());
		goto end;
	}

	rc = EVP_VerifyInit(&vfctx, DIGESTTYP());
	if (rc != EVPOK) {
		ERROR("EVP_VerifyInit returns %d (%s)", rc, strerror(errno));
		return;
	}

	// Read associations

	c = (char*) data;
	end = (char*) (data + len);

	while (c && c < end 
		   && memcmp(c, signature_mark, strlen(signature_mark))) 
	{
		string aname;
		string digest;
		char* eol, *sep, *str;

		sep = strchr(c, ' ');
		if (!sep) {
			ERROR("broken file '%s'", filename.c_str());
			goto end;
		}
		str = strchr(sep + 1, '*');
		if (!str) {
			ERROR("broken file '%s'", filename.c_str());
			goto end;
		}
		eol = strchr(str + 1, '\n');
		if (!eol) {
			ERROR("broken file '%s'", filename.c_str());
			goto end;
		}
		aname.append(sep + 2, eol - str - 1);
		digest.append(c, sep - c);
		DEBUG(1, "%s => %s", aname.c_str(), digest.c_str());
		c = eol + 1;
		m_contents[aname] = digest;
	}

	// Check signature
	if (memcmp(c, signature_mark, strlen(signature_mark)) == 0) {
		unsigned char mdref [255];
		size_t mdlen = 0;
		
		// Compute the current digest
		DEBUG(1, "checking %d bytes of data", c - (char*)data);
		rc = EVP_VerifyUpdate(&vfctx, data, c - (char*)data);
		if (rc != EVPOK) {
			ERROR("EVP_DigestUpdate returns %d (%d)", rc, errno);
			return;
		}

		// Read the stored signature
		while (*c && *c != '\n') c++;
		if (*c == '\n') {
			c++;
			while (*c && *c != '-' && mdlen < sizeof(mdref)) {
				if (*c != '\n') {
					mdref[mdlen++] = hex2bin(c);
					c += 2;
				} else
					c++;
			}
		}

		DEBUG(1, "loaded %d bytes of signature", mdlen);
		rc = EVP_VerifyFinal(&vfctx, mdref, mdlen, X509_get_pubkey(bb5_get_cert()));
		if (rc != EVPOK) {
			ERROR("EVP_VerifyFinal returns %d", rc);
			return;
		} else {
			DEBUG(1, "Checksum file verifies OK");
		}

	} else
		ERROR("invalid signature");

  end:
	unmap_file(data, fd, len);
}


storage::~storage()
{
	ccount--;
	if (ccount == 0)
		bb5_finish();
}


size_t
storage::get_files(stringlist& names)
{
	size_t pos = 0;

	for (
		map<string, string>::const_iterator ii = m_contents.begin();
		ii != m_contents.end();
		ii++
	) {
		names.push_back(ii->first.c_str());
	}
	return(pos);
}


unsigned char* 
storage::map_file(const char* pathname, int* fd, ssize_t* len)
{
	int lfd;
	struct stat fs;
	unsigned char* res;
	ssize_t llen = 0;

	lfd = open(pathname, O_RDONLY);
	if (lfd < 0) {
		return((unsigned char*)MAP_FAILED);
	}
	
	if (fstat(lfd, &fs) == -1) {
		close(lfd);
		ERROR("cannot stat '%s'", pathname);
		return((unsigned char*)MAP_FAILED);
	}
	*len = llen = fs.st_size;
	DEBUG(1, "'%s' is %d bytes long", pathname, llen);
	if (llen == 0) {
		close(lfd);
		ERROR("'%s' is empty", pathname);
		return((unsigned char*)MAP_FAILED);
	}

	res = (unsigned char*)mmap(NULL, llen + 1, PROT_READ | PROT_WRITE, 
							   MAP_PRIVATE, lfd, 0);
	if (res == MAP_FAILED) {
		close(lfd);
		ERROR("cannot mmap '%s' of %d bytes", pathname, llen);
		return((unsigned char*)MAP_FAILED);
	} else {
		*(res + llen) = '\0';
	}
	*fd = lfd;
	return(res);
}


void
storage::unmap_file(unsigned char* data, int fd, ssize_t len)
{
	if (data)
		munmap(data, len);
	if (fd >= 0)
		close(fd);
}


void
storage::compute_digest(const char* pathname, string& digest)
{
	int fd, rc;
	unsigned char* data;
	ssize_t len;
	unsigned int mdlen;
	char hlp [3];
	EVP_MD_CTX mdctx;
	unsigned char md[DIGESTLEN];

	digest.clear();
	data = map_file(pathname, &fd, &len);
	if (data == MAP_FILE) {
		ERROR("cannot map '%s'", pathname);
		return;
	}

	EVP_MD_CTX_init(&mdctx);
	rc = EVP_DigestInit(&mdctx, DIGESTTYP());
	if (rc != EVPOK) {
		ERROR("EVP_DigestInit returns %d (%s)", rc, strerror(errno));
		return;
	}

	DEBUG(1, "computing digest over %d bytes", len);
	rc = EVP_DigestUpdate(&mdctx, data, len);
	if (rc != EVPOK) {
		ERROR("EVP_DigestUpdate returns %d (%d)", rc, errno);
		return;
	}

	rc = EVP_DigestFinal(&mdctx, md, &mdlen);
	if (rc != EVPOK) {
		ERROR("EVP_DigestFinal returns %d (%d)", rc, errno);
		return;
	}
	if ((int)mdlen != DIGESTLEN) {
		ERROR("Digestlen mismatch (%d != %d)", mdlen, DIGESTLEN);
		return;
	}

	for (unsigned int i = 0; i < mdlen; i++) {
		sprintf(hlp, "%02x", md[i]);
		digest.append(hlp,2);
	}
	unmap_file(data, fd, len);
	EVP_MD_CTX_cleanup(&mdctx);
}


void
storage::add_file(const char* pathname)
{
	string truename;
	string digest;

	absolute_pathname(pathname, truename);
	compute_digest(truename.c_str(), digest);
	m_contents[truename] = digest;
	DEBUG(1, "%s => %s", truename.c_str(), digest.c_str());
}


void
storage::remove_file(const char* pathname)
{
	string truename = pathname;
	// map<string,string>::const_iterator ii;
	map<string,string>::iterator ii;

	m_contents.erase(m_contents.find(truename));
}

bool 
storage::verify_file(const char* pathname)
{
	string digest;
	string truename;
	map<string,string>::iterator ii;

	absolute_pathname(pathname, truename);
	ii = m_contents.find(truename);

	if (ii == m_contents.end()) {
		DEBUG(0, "'%s' not found", truename.c_str());
		return(false);
	}

	if (ii->first == truename) {
		compute_digest(truename.c_str(), digest);
		return(ii->second == digest);
	} else
		return(false);
}



static void 
checked_write(int to_fd, const char* str, EVP_MD_CTX* signature)
{
	ssize_t written, len = strlen(str);
	
	written = write(to_fd, str, len);
	if (written < len) {
		// TODO: Throw an exception
		ERROR("failed to write %d bytes (written %d)", len, written);
	} else if (signature)
		EVP_SignUpdate(signature, str, len);
}

void
storage::commit(void)
{
	string filename;
	int rc, fd = -1;
	EVP_MD_CTX signctx;
	unsigned char signmd[255];

	filename = sec_root;
	filename.append("/");
	filename.append(m_name);

	fd = creat(filename.c_str(), S_IRUSR | S_IWUSR);
	if (fd < 0) {
		ERROR("cannot create '%s'", filename.c_str());
		return;
	}

	EVP_SignInit(&signctx, EVP_sha1());

	for (
		map<string, string>::const_iterator ii = m_contents.begin();
		ii != m_contents.end();
		ii++
	) {
		// Use sha1sum compatible output
		const char* tmp = ii->second.c_str();
		if (!tmp) {
			ERROR("m_contents broken");
			goto end;
		}
		checked_write(fd, tmp, &signctx);
		checked_write(fd, " *", &signctx);
		tmp = ii->first.c_str();
		if (!tmp) {
			ERROR("m_contents broken");
			goto end;
		}
		checked_write(fd, tmp, &signctx);
		checked_write(fd, "\n", &signctx);
	}

	rc = bb5_rsakp_sign(&signctx, signmd, sizeof(signmd));
	if (rc > 0) {
		string signature;
		char tmp[3];
		int cols = 0;

		checked_write(fd, signature_mark "\n", NULL);

		for (size_t i = 0; i < (size_t)rc; i++) {
			sprintf(tmp, "%02x", signmd[i]);
			signature.append(tmp, 2);
			if (++cols == 32) {
				signature.append("\n");
				cols = 0;
			}
		}
		checked_write(fd, signature.c_str(), NULL);
	}

end:
	close(fd);
}

} // extern "C"
