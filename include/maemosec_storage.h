/* -*- mode:c; tab-width:4; c-basic-offset:4; -*-
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

/**
 \file maemosec_storage.h
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

#include "maemosec_common.h"

/**
 * \namespace maemosec_sec
 * \brief Namespace maemosec_sec means "NGSW Security"
 */

namespace maemosec {

	/**
	 * \class storage
	 * \brief A secure file container.
	 * 
	 * This class is used to ensure file integrity by local 
	 * signing and prevent unauthorized reading by encryption.
	 */

	class storage
	{
	public:

		/**
		 * \brief The visibility of a storage. Defined
		 * when a storage is created and cannot be changed
		 * afterwards.
		 */
		typedef enum {vis_shared, vis_private} visibility_t;
		
		/**
		 * \brief The protection level of a storage. Defined
		 * when a storage is created and cannot be changed
		 * afterwards.
		 */
		typedef enum {prot_signed, prot_encrypted} protection_t;

		/**
		 * \brief Create a new storage or open an existing one
		 * \param name (in) The logical name of the storage
		 * \param visibility (in) The visibility of the storage.
		 * \param protection (in) The protection level of the storage.
		 */
		storage(const char* name, visibility_t visibility, protection_t protection);

		/**
		 * \brief Destructor. Release memory allocations.
		 */
		~storage();

		/**
		 * \brief A list of strings
		 */
		typedef std::vector<const char*> stringlist;

		/**
		 * \brief Get a list of the files in the storage
		 */
		size_t get_files(stringlist &names);

		/**
		 * \brief Release the given stringlist
		 */
		void release(stringlist &list);


		/**
		 * \brief Check if the storage contains the given file
		 */
		bool contains_file(const char* pathname);

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
		 * in \see commit
		 * \param pathname (in) The name of the file
		 * \returns true, if the checksum matches
		 */
		bool verify_file(const char* pathname);

		/**
		 * \brief Read an entire file into memory. Verification
		 * and decryption are performed automatically.
		 * \param pathname (in) The name of the file
		 * \param to_buf (out) The buffer where the 
		 * file contents are copied. Decryption is done
		 * automatically if needed. The parameter
		 * needs not to have any value at entry.
		 * \param bytes (out) The number of bytes read,
		 * equals the file size.
		 * \returns 0 on success, otherwise an error code
		 * Use \see release_buffer to release the returned
		 * buffer after use.
		 */
		int get_file(const char* pathname, 
					 unsigned char** to_buf, 
					 ssize_t* bytes);
	
		/**
		 * \brief Release a buffer
		 * \param buf The buffer to be released, returned 
		 * by \see get_file
		 */
		void release_buffer(unsigned char* buf);
	
		/**
		 * \brief Write a file to the filesystem. Encrypt if needed.
		 * \param pathname (in) The name of the file to write. If the file
		 * does not yet exist in the storage, it's added.
		 * \param data (in) The data to be written and optionally
		 * encrypted
		 * \param bytes (in) The number of bytes to be written
		 * \returns 0 on success, otherwise and error code
		 */
		int put_file(const char* pathname, unsigned char* data, ssize_t bytes);

		/**
		 * \brief Sign the storage
		 * Write the checksums into the storage file. A file that has
		 * been saved by \see put_file gets the checksum from what was
		 * written, regardless of what is on the disk, othewise the
		 * checksum is computed according to the current contents of 
		 * the file.
		 */
		void commit();

		/**
		 * \brief How many files the storage contains
		 * \returns The number of files in the storage
		 */
		int nbrof_files();

		/**
		 * \brief Logical name of the storage
		 */
		const char* name();

		/**
		 * \brief Location of the storage
		 */
		const char* filename();

		  
		/**
		 * \brief Iterate through storages of the given visibility and
		 * protection
		 * \param of_visibility (in) vis_shared or vis_private
		 * \param of_protection (in) prot_signed or prot_encrypted
		 * \param matching_names (in) a regular expression for the storage name
		 * \param cb_func (in) a callback function, the storage name as the
		 * payload parameter.
		 * \param ctx (in) the context pointer for the callback
		 * \return if < 0, 0 - error code
		 *         if >= 0, the value returned by the callback function
		 */
		static int iterate_storage_names(storage::visibility_t of_visibility, 
							  storage::protection_t of_protection, 
							  const char* matching_names,
							  maemosec_callback* cb_func,
							  void* ctx);

	private:
		protection_t m_prot;
		std::map<std::string, std::string> m_contents;
		std::string m_name;
		std::string m_filename;
		unsigned char* m_symkey;
		int m_symkey_len;

		void init_storage(const char* name, 
						  visibility_t visibility, 
						  protection_t protect);
		bool compute_digest(unsigned char* data, 
							ssize_t bytes, 
							std::string& digest);
		void compute_digest_of_file(const char* pathname, 
									std::string& digest);
		unsigned char* map_file(const char* pathname, 
								int prot, 
								int* fd, 
								ssize_t* len, 
								ssize_t* rlen);
		void unmap_file(unsigned char* data, 
						int fd, 
						ssize_t len);
		bool decrypt_file(const char* pathname, 
						  unsigned char** to_buf, 
						  ssize_t* len, 
						  std::string& digest);
		bool encrypt_file(const char* pathname, 
						  unsigned char* from_buf, 
						  ssize_t len, 
						  std::string& digest);
		bool encrypt_file_in_place(const char* pathname, 
								   std::string& digest);
		bool cryptop(int op, 
					 unsigned char* data, 
					 unsigned char* to, 
					 ssize_t len, 
					 EVP_MD_CTX* digest);
		bool set_aes_key(int op, 
						 AES_KEY *ck);
		ssize_t encrypted_length(ssize_t of_data);

	};


};

#endif
