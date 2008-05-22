/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include "sec_storage.h"
using namespace ngsw_sec;

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "sec_common.h"
#include "libbb5stub.h"

#define DIGESTTYP EVP_sha1
#define DIGESTLEN EVP_MD_size(DIGESTTYP())
#define EVPOK 1
#define SYMKEYLEN 32

// This is just pretty printing; wrap long hexadecimal 
// lines after this many pairs
#define WRAPPOINT 32

static const char sec_root[] = "/secure";
// static X509_STORE* certs = NULL;
static int ccount = 0;

#define signature_mark "SIGNATURE:"
#define key_mark       "CRYPTOKEY:"

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


void
storage::init_storage(const char* name, protection_t protect) 
{
	char* end, *c = NULL;
	unsigned char* data = NULL;
	string filename;
	int fd = -1, rc;
	ssize_t len, rlen;
	EVP_MD_CTX vfctx;

	m_name = name;
	m_symkey = NULL;
	m_symkey_len = SYMKEYLEN;
	m_prot = protect;

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

	data = map_file(filename.c_str(), O_RDONLY, &fd, &len, &rlen);
	if (data == MAP_FAILED) {

		// Generate a new symkey
		if (m_prot == prot_encrypt) {
			m_symkey = (unsigned char*)malloc(m_symkey_len);
			if (!m_symkey) {
				ERROR("allocation error");
			}
			rc = bb5_get_random(m_symkey, m_symkey_len);
			if (rc != m_symkey_len) {
				ERROR("cannot generate new encryption key");
			}
			// TODO: encrypt the key by BB5 secret key
		}

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
	if (memcmp(c, signature_mark, strlen(signature_mark)) == 0) 
	{
		// TODO: remove ugly plain number
		unsigned char mdref [128];
		// unsigned char mdref [DIGESTLEN];
		size_t mdlen = 0;
		
		// Compute the current digest
		DEBUG(1, "checking %d bytes of data", c - (char*)data);
		rc = EVP_VerifyUpdate(&vfctx, data, c - (char*)data);
		if (rc != EVPOK) {
			ERROR("EVP_DigestUpdate returns %d (%d)", rc, errno);
			return;
		}

		// Read the stored signature
		while (c < end && *c != '\n') 
			c++;
		if (*c == '\n') {
			c++;
			while (c < end && *c && mdlen < sizeof(mdref)) {
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

	if (c < end && *c == '\n')
		c++;

	// Check if this is an encrypted storage
	if (c + strlen(key_mark) >= end
		|| memcmp(c, key_mark, strlen(key_mark)) != 0)
	{
		if (m_prot == prot_encrypt) {
			ERROR("missing encryption key");
			goto end;
		}
	} else {
		// There is an encryption key
		unsigned char* to; 
		int keylen = 0;

		m_prot = prot_encrypt;
		if (!m_symkey) {
			m_symkey = (unsigned char*)malloc(m_symkey_len);
			if (!m_symkey) {
				ERROR("allocation error");
			}
		}
		c += strlen(key_mark);
		if (c < end && *c == '\n')
			c++;
		to = m_symkey;
		while (c < end && keylen < m_symkey_len) {
			if (*c != '\n') {
				*to++ = hex2bin(c);
				keylen++;
				c += 2;
			} else
				c++;
		}
		if (keylen != m_symkey_len) {
			ERROR("corrupt encryption key");
			goto end;
		}
	}

  end:
	unmap_file(data, fd, len);
}


storage::storage(const char* name)
{
	init_storage(name, prot_sign);
}


storage::storage(const char* name, protection_t protect) 
{
	init_storage(name, protect);
}


storage::~storage()
{
	ccount--;
	if (ccount == 0)
		bb5_finish();
	if (m_symkey)
		free(m_symkey);
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


bool
storage::contains_file(const char* pathname)
{
	string truename;
	map<string,string>::iterator ii;

	absolute_pathname(pathname, truename);
	ii = m_contents.find(truename);
	return (ii != m_contents.end());
}


unsigned char* 
storage::map_file(const char* pathname, int mode, int* fd, ssize_t* len, ssize_t* rlen)
{
	int lfd, mflags, mprot;
	struct stat fs;
	unsigned char* res;
	ssize_t llen = 0;

	lfd = open(pathname, mode);
	if (lfd < 0) {
		return((unsigned char*)MAP_FAILED);
	}
	
	if (fstat(lfd, &fs) == -1) {
		close(lfd);
		ERROR("cannot stat '%s'", pathname);
		return((unsigned char*)MAP_FAILED);
	}
	*rlen = llen = fs.st_size;
	DEBUG(1, "'%s' is %d bytes long", pathname, llen);
	if (llen == 0) {
		close(lfd);
		ERROR("'%s' is empty", pathname);
		return((unsigned char*)MAP_FAILED);
	}
	/*
	 * TODO: when reading an encrypted file, how to make sure
	 * that decrypted pages are not swapped out and encrypted
	 * content fetched from disk by mmu?
	 */
	if (mode == O_RDONLY) {
		mflags = MAP_PRIVATE;
		if (m_prot == prot_sign)
			mprot = PROT_READ;
		else
			mprot = PROT_READ | PROT_WRITE;
	} else {
		mflags = MAP_SHARED;
		mprot = PROT_READ | PROT_WRITE;
		if ((llen % AES_BLOCK_SIZE) == 0)
			llen += 1;
		else
			llen += AES_BLOCK_SIZE - (llen % AES_BLOCK_SIZE) + 1;
	}
	
	res = (unsigned char*)mmap(NULL, llen, mprot, mflags, lfd, 0);

	if (res == MAP_FAILED) {
		close(lfd);
		ERROR("cannot mmap '%s' of %d bytes", pathname, llen);
		return((unsigned char*)MAP_FAILED);
	}
	*len = llen;
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
	ssize_t len, rlen;
	unsigned int mdlen;
	char hlp [3];
	EVP_MD_CTX mdctx;
	unsigned char md[DIGESTLEN];

	digest.clear();
	data = map_file(pathname, O_RDONLY, &fd, &len, &rlen);
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
	DEBUG(1, "Computed digest is '%s'", digest.c_str());
}


void
storage::add_file(const char* pathname)
{
	string truename;
	string digest;

	absolute_pathname(pathname, truename);
	if (contains_file(truename.c_str())) {
		DEBUG(0, "'%s' already belongs to '%s'", 
			  truename.c_str(), m_name.c_str());
		return;
	}
	if (m_prot == prot_encrypt) {
		if (!encrypt_file(truename.c_str(), digest)) {
			return;
		}
	} else
		compute_digest(truename.c_str(), digest);
	m_contents[truename] = digest;
	DEBUG(1, "%s => %s", truename.c_str(), digest.c_str());
}


void
storage::remove_file(const char* pathname)
{
	string truename;

	absolute_pathname(pathname, truename);
	if (!contains_file(truename.c_str())) {
		DEBUG(0, "'%s' not found", truename.c_str());
		return;
	}
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
		if (m_prot == prot_encrypt)
			decrypt_file(truename.c_str(), NULL, NULL, digest);
		else
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
	char tmp[3];
	int cols;

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
		
		checked_write(fd, signature_mark "\n", NULL);

		cols = 0;
		for (size_t i = 0; i < (size_t)rc; i++) {
			sprintf(tmp, "%02x", signmd[i]);
			signature.append(tmp, 2);
			if (++cols == WRAPPOINT) {
				signature.append("\n");
				cols = 0;
			}
		}
		checked_write(fd, signature.c_str(), NULL);
	}

	if (m_prot == prot_encrypt) {
		string key;
		checked_write(fd, key_mark "\n", NULL);

		cols = 0;
		for (int i = 0; i < m_symkey_len; i++) {
			sprintf(tmp, "%02x", m_symkey[i]);
			key.append(tmp, 2);
			if (++cols == WRAPPOINT) {
				key.append("\n");
				cols = 0;
			}
		}
		checked_write(fd, key.c_str(), NULL);
	}

end:
	close(fd);
}


bool
storage::cryptop(int op, unsigned char* data, unsigned char* to, ssize_t len, EVP_MD_CTX* digest)
{
	int rc;
	AES_KEY ck;
	unsigned char *from;
	unsigned char ibuf[AES_BLOCK_SIZE];
	unsigned char obuf[AES_BLOCK_SIZE];

	if (len % AES_BLOCK_SIZE != 0) {
		ERROR("invalid length %d", len);
		return(false);
	}

	// TODO: Decrypt the symkey

	if (op == AES_ENCRYPT)
		rc = AES_set_encrypt_key(m_symkey, 8 * m_symkey_len, &ck);
	else if (op == AES_DECRYPT)
		rc = AES_set_decrypt_key(m_symkey, 8 * m_symkey_len, &ck);
	else {
		ERROR("unsupported cryptop %d", op);
		return(false);
	}

	// TODO: zero memory used by the plaintext symkey
	DEBUG(1, "AES set key ret %d", rc);

	from = data;
	while (len > 0) {
		if (op == AES_ENCRYPT) {
			// TODO: check if AES can be performed in-place without
			// memcpy
			AES_encrypt(from, obuf, &ck);
			if (digest) {
				rc = EVP_DigestUpdate(digest, from, AES_BLOCK_SIZE);
				if (rc != EVPOK) {
					ERROR("EVP_DigestUpdate returns %d (%d)", rc, errno);
				}
			}
			memcpy(from, obuf, AES_BLOCK_SIZE);
		} else {
			AES_decrypt(from, obuf, &ck);
			if (digest) {
				rc = EVP_DigestUpdate(digest, obuf, AES_BLOCK_SIZE);
				if (rc != EVPOK) {
					ERROR("EVP_DigestUpdate returns %d (%d)", rc, errno);
					abort();
				}
			}
			if (to) {
				memcpy(to, obuf, AES_BLOCK_SIZE);
				to += AES_BLOCK_SIZE;
			}
		}
		from += AES_BLOCK_SIZE;
		len -= AES_BLOCK_SIZE;
	}
	memset(&ck, '\0', sizeof(ck));
	return(true);
}


bool
storage::encrypt_file(const char* pathname, string& digest)
{
	unsigned char* data;
	ssize_t len, rlen;
	int fd, rc;
	bool res;
	unsigned int mdlen;
	char hlp [3];
	EVP_MD_CTX mdctx;
	unsigned char md[DIGESTLEN];


	data = map_file(pathname, O_RDWR, &fd, &len, &rlen);
	if (!data) {
		return(false);
	}

	// Fill the tail with zeroes
	memset(data + rlen, '\0', len - rlen);

	EVP_MD_CTX_init(&mdctx);
	rc = EVP_DigestInit(&mdctx, DIGESTTYP());
	if (rc != EVPOK) {
		ERROR("EVP_DigestInit returns %d (%s)", rc, strerror(errno));
		return(false);
	}

	res = cryptop(AES_ENCRYPT, data, NULL, len - 1, &mdctx);
	if (res) {
		*(data + len - 1) = len - rlen;
	}

	// write the tail
	DEBUG(0, "lseek ret %d", lseek(fd, rlen, SEEK_SET));
	DEBUG(0, "write ret %d", write(fd, data + rlen, len - rlen));
	unmap_file(data, fd, len);

	rc = EVP_DigestFinal(&mdctx, md, &mdlen);
	if (rc != EVPOK) {
		ERROR("EVP_DigestFinal returns %d (%d)", rc, errno);
		return(false);
	}

	if ((int)mdlen != DIGESTLEN) {
		ERROR("Digestlen mismatch (%d != %d)", mdlen, DIGESTLEN);
		return(false);
	}

	for (unsigned int i = 0; i < mdlen; i++) {
		sprintf(hlp, "%02x", md[i]);
		digest.append(hlp,2);
	}

	EVP_MD_CTX_cleanup(&mdctx);
	DEBUG(1, "Computed digest is '%s'", digest.c_str());

	return(res);
}


bool
storage::decrypt_file(const char* pathname, unsigned char** to_buf, ssize_t* len, string& digest)
{
	int fd, rc;
	unsigned char* data, *locbuf;
	ssize_t llen, rlen;
	unsigned int mdlen;
	char hlp [3];
	EVP_MD_CTX mdctx;
	unsigned char md[DIGESTLEN];

	digest.clear();
	data = map_file(pathname, O_RDONLY, &fd, &llen, &rlen);
	if (data == MAP_FILE) {
		ERROR("cannot map '%s'", pathname);
		return(false);
	}
	rlen -= *(data + llen - 1);
	DEBUG(1, "real len is %d bytes", rlen);
	if (to_buf) {
		*to_buf = locbuf = (unsigned char*) malloc (rlen);
		if (!locbuf) {
			ERROR("cannot allocate %d bytes", rlen);
			return(false);
		}
		memset(locbuf, '\0', rlen);
	} else
		locbuf = NULL;

	EVP_MD_CTX_init(&mdctx);
	rc = EVP_DigestInit(&mdctx, DIGESTTYP());
	if (rc != EVPOK) {
		ERROR("EVP_DigestInit returns %d (%s)", rc, strerror(errno));
		return(false);
	}

	if (!cryptop(AES_DECRYPT, data, locbuf, llen - 1, &mdctx)) {
		ERROR("Decryption failed");
		return(false);
	}

	rc = EVP_DigestFinal(&mdctx, md, &mdlen);
	if (rc != EVPOK) {
		ERROR("EVP_DigestFinal returns %d (%d)", rc, errno);
		return(false);
	}
	if ((int)mdlen != DIGESTLEN) {
		ERROR("Digestlen mismatch (%d != %d)", mdlen, DIGESTLEN);
		return(false);
	}

	for (unsigned int i = 0; i < mdlen; i++) {
		sprintf(hlp, "%02x", md[i]);
		digest.append(hlp,2);
	}
	unmap_file(data, fd, llen);
	*len = rlen;
	EVP_MD_CTX_cleanup(&mdctx);
	DEBUG(1, "Computed digest is '%s'", digest.c_str());
}


int
storage::get_file(const char* pathname, int* handle, unsigned char** to_buf, ssize_t* bytes)
{
	string truename, digest;
	ssize_t rlen;

	if (!to_buf || !bytes) {
		return(EINVAL);
	}

	absolute_pathname(pathname, truename);
	if (!contains_file(truename.c_str())) {
		ERROR("'%s' not found", truename.c_str());
		return(EINVAL);
	}

	if (m_prot == prot_encrypt) {
		if (decrypt_file(truename.c_str(), to_buf, bytes, digest)) {
			if (digest == m_contents[truename]) {
				*handle = -1;
				return(0);
			} else {
				ERROR("Digest does not match");
				return(-1);
			}
		} else
			return(-1);
	} else {
		// TODO: this should be made a bit more atomaric
		if (!verify_file(pathname)) {
			ERROR("'%s' does not match checksum", truename.c_str());
			return(EINVAL);
		}
		*to_buf = map_file(truename.c_str(), O_RDONLY, handle, bytes, &rlen);
		if (*to_buf) {
			return(0);
		} else
			return(errno);
	}
}


void
storage::close_file(int handle, unsigned char** buf, ssize_t bytes)
{
	if (m_prot == prot_encrypt) {
		free(*buf);
	} else {
		unmap_file(*buf, handle, bytes);
		*buf = NULL;
	}
}
