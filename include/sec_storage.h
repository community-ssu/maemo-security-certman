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

// STL headers
#include <string.h>

#include <string>
#include <vector>
#include <map>
using namespace std;

namespace ngsw_sec {

	class storage
	{
	private:
		map<string, string> m_contents;
		string m_name;
		int m_fd;

		void compute_digest(const char* pathname, string& digest);
		unsigned char* map_file(const char* pathname, int* fd, ssize_t* len);
		void unmap_file(unsigned char* data, int fd, ssize_t len);

	public:

		/**
		 * \brief The protection level astorage
		 */
		typedef enum {prot_sign, prot_encrypt} protection_t;
		
		/**
		 * \brief Create a new storage or open an existing one
		 * \param name (in) The logical name of the storage
		 * \param protect (in) The protection level of the storage
		 */
		storage(const char* name, protection_t protect);

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
		 * \brief Add a file into the storage
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
		 * \param handle (out) A handle to the file
		 * \param to_buf (out) The buffer where the 
		 * (plaintext) contents are copied. The parameter
		 * needs not to have any value at entry.
		 * \param bytes (out) The number of bytes available
		 * in the buffer.
		 * \returns 0 on success, otherwise an error code
		 */
		int get_file(const char* pathname, 
					 int* handle, 
					 unsigned char** to_buf, 
					 size_t* bytes);

		/**
		 * \brief Write a file to the filesystem.
		 * \param handle (in) The handle returned from \ref get_file or
		 * \ref create_file
		 * \param data (in) The data to be written and optionally
		 * encrypted
		 * \param (in) The number of bytes to be written
		 * \returns 0 on success, otherwise and error code
		 */
		int put_file(int handle, unsigned char* data, size_t bytes);

		/*
		 * \brief Close an open file
		 * \param handle (in) The handle returned from \ref get_file or
		 * \ref create_file
		 * \param buf (in) The buffer returned from \ref get_file or
		 * NULL
		 */
		void close_file(int handle, unsigned char** buf);
		
		/*
		 * \brief Sign the storage
		 * Write the checksums into the storage file. A file that has
		 * been saved by \ref put_file gets the checksum from what was
		 * written, regardless of what is on the disk, othewise the
		 * checksum is computed according to the current contents of 
		 * the file.
		 */
		void commit();

	};
};

#endif
