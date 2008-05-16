/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

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
		typedef enum {prot_sign, prot_encrypt} protection_t;
		
		/*
		 * Open and close storage
		 */
		storage(const char* name, protection_t protect);
		~storage();

		/*
		 * Fileset operations
		 */
		typedef vector<const char*> stringlist;
		size_t get_files(stringlist &names);

		void add_file(const char* pathname);
		void remove_file(const char* pathname);
		bool verify_file(const char* pathname);

		/*
		 * Operations on entire file contents. Verification and 
		 * encryption/decryption are performed automatically.
		 * TODO: should there also be read and write for reading
		 * and writing parts of the file?
		 */
		int get_file(const char* pathname, 
					 int* handle, 
					 unsigned char** to_buf, 
					 size_t* bytes);
		int put_file(int handle, unsigned char* data, size_t bytes);
		/*
		 * Release resources
		 */
		void close_file(int handle, unsigned char** buf);
		
		/*
		 * Sign storage
		 */
		void commit();

	};
};

#endif
