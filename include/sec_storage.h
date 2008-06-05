// -*- mode:c++; tab-width:4; c-basic-offset:4; -*-
/**
 \file sec_storage.h
 \ingroup sec_storage
 \brief Protected storage library.

 This library provides functions for protetcting files against
 unauthorized access by encryption and off-line tampering by
 signing. Files are grouped into storages, where new files can
 be added. When signing, the checksums of each files are stored
 into a separate list, which is the signed by using a secret key.
 When the storage is opened, the checksums are verified to detect
 any covert changes. 
 
 In an encrypted storage the contents is also automatically encrypted
 by using an automatically generated symmetric key.

*/


#ifndef SEC_STORAGE_H
#define SEC_STORAGE_H

#include <string.h>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/aes.h>

// STL headers
#include <string>
#include <vector>
#include <map>
using namespace std;

namespace ngsw_sec {

	class storage
	{
	public:

		/**
		 * \brief The protection level of a storage. Defined
		 * when a storage is created and cannot be changed
		 * afterwards.
		 */
		typedef enum {prot_signed, prot_encrypted} protection_t;

		/**
		 * \brief The visibility of a storage. Defined
		 * when a storage is created and cannot be changed
		 * afterwards.
		 */
		typedef enum {vis_shared, vis_private} visibility_t;
		
		/**
		 * \brief Create a new storage or open an existing one
		 * \param name (in) The logical name of the storage
		 * \param visibility (in) The visibility of the storage.
		 * \param protect (in) The protection level of the storage.
		 * If the storage exists already, the parameter is 
		 * ignored (or should an error be raised if the parameter
		 * does not match?)
		 */
		storage(const char* name, visibility_t visibility, protection_t protection);

#if 0
		/**
		 * \brief Open an existing storage
		 * \param name (in) The logical name of the storage
		 */
		storage(const char* name);
#endif

		/**
		 * \brief Destructor. Release memory allocations.
		 */
		~storage();

		/**
		 * \brief A list of strings
		 */
		typedef vector<const char*> stringlist;

		/**
		 * \brief Get a list of the files in the storage
		 */
		size_t get_files(stringlist &names);

		/**
		 * \brief Add an existing file into the storage
		 * \param pathname (in) The name of the file. Relative pathnames
		 * are automatically converted to absolute.
		 */
		void add_file(const char* pathname);

		/**
		 * \brief Remove a file from the storage
		 * \param pathname The name of the file
		 */
		void remove_file(const char* pathname);

		/**
		 * \brief Check that a file matches the checksum stored
		 * in \ref commit
		 * \param pathname (in) The name of the file
		 * \returns true, if the checksum matches
		 */
		bool verify_file(const char* pathname);

		/*
		 * \brief Read an entire file into memory. Verification
		 * and decryption are performed automatically.
		 * \param pathname (in) The name of the file
		 * \param to_buf (out) The buffer where the 
		 * file contents are copied. Decryption is done
		 * automatically if needed. The parameter
		 * needs not to have any value at entry. Use 
		 * \ref release_buffer to release the returned
		 * buffer after use.
		 * \param bytes (out) The number of bytes available
		 * in the buffer.
		 * \returns 0 on success, otherwise an error code
		 */
		int get_file(const char* pathname, 
					 unsigned char** to_buf, 
					 ssize_t* bytes);
	
		/**
		 * \brief Release a buffer
		 * \param buf The buffer to be released, returned 
		 * by \ref get_file
		 */
		void release_buffer(unsigned char* buf) {if (buf) free(buf);}
	
		/**
		 * \brief Write a file to the filesystem. Encrypt if needed.
		 * \param handle (in) The handle returned from \ref get_file or
		 * \ref create_file
		 * \param data (in) The data to be written and optionally
		 * encrypted
		 * \param (in) The number of bytes to be written
		 * \returns 0 on success, otherwise and error code
		 */
		int put_file(const char* pathname, unsigned char* data, ssize_t bytes);

		/*
		 * \brief Sign the storage
		 * Write the checksums into the storage file. A file that has
		 * been saved by \ref put_file gets the checksum from what was
		 * written, regardless of what is on the disk, othewise the
		 * checksum is computed according to the current contents of 
		 * the file.
		 */
		void commit();

		int nbrof_files();

	private:
		protection_t m_prot;
		map<string, string> m_contents;
		string m_name;
		string m_filename;
		int m_fd;
		unsigned char* m_symkey;
		int m_symkey_len;

		void init_storage(const char* name, visibility_t visibility, protection_t protect);
		bool contains_file(const char* pathname);
		bool compute_digest(unsigned char* data, ssize_t bytes, string& digest);
		void compute_digest_of_file(const char* pathname, string& digest);
		unsigned char* map_file(const char* pathname, int prot, int* fd, ssize_t* len, ssize_t* rlen);
		void unmap_file(unsigned char* data, int fd, ssize_t len);
		bool decrypt_file(const char* pathname, unsigned char** to_buf, ssize_t* len, string& digest);
		bool encrypt_file(const char* pathname, unsigned char* from_buf, ssize_t len, string& digest);
		bool encrypt_file_in_place(const char* pathname, string& digest);
		bool cryptop(int op, unsigned char* data, unsigned char* to, ssize_t len, EVP_MD_CTX* digest);
		bool set_aes_key(int op, AES_KEY *ck);
		ssize_t encrypted_length(ssize_t of_data);

	};

};

#endif
