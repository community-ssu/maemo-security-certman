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

#include "maemosec_common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <linux/limits.h>
#include <dirent.h>
#include <regex.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

/*
 * Reset this variable to build stores in scratchbox
 */
int resolve_symlinks = 1;

extern "C" 
{

#define DYNHEX_STRINGS 10
	int eh_registered = 0;
	int dynhexpos = 0;
	char* dynhexring[DYNHEX_STRINGS] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	static void clean_dynhexring(void)
	{
		int i;
		for (i = 0; i < DYNHEX_STRINGS; i++) {
			if (dynhexring[i])
				free(dynhexring[i]);
		}
		MAEMOSEC_DEBUG(1, "Exit application");
	}

	const char* dynhex(const unsigned char* d, unsigned len)
	{
		int i;
		char *t, *s = (char*)malloc(2*len + 1);

		if (NULL == s) {
			abort();
		}
		strcpy(s, "");
		for (t = s, i = 0; i < len; i++, t += 2) {
			sprintf(t, "%02x", *d++);
		}
		dynhexring[dynhexpos] = s;
		dynhexpos = (dynhexpos + 1) % DYNHEX_STRINGS;
		if (dynhexring[dynhexpos]) {
			free(dynhexring[dynhexpos]);
			dynhexring[dynhexpos] = NULL;
		}
		if (!eh_registered) {
			atexit(clean_dynhexring);
			eh_registered = 1;
		}
		return(s);
	}

	bool
	absolute_pathname(const char* pathname, string& to_this)
	{
		int rc, curdirh = -1;
		struct stat fs;
		string dirname;
		char cdirname [PATH_MAX];
		char* dirsep = NULL;
		bool is_local = false;
		char* tgtname = NULL;
		size_t rv;

		if ('\0' == *pathname)
			return(false);

		rc = lstat(pathname, &fs);
		if (rc == -1) {
			MAEMOSEC_ERROR("cannot stat '%s' (%s)", pathname, strerror(errno));
			return(false);
		}

		if (S_ISLNK(fs.st_mode)) {
			tgtname = (char*)malloc(PATH_MAX);
			if (!tgtname) {
				MAEMOSEC_ERROR("cannot allocate");
				goto fail;
			}
			rv = readlink(pathname, tgtname, PATH_MAX - 1);
			if (rv == -1) {
				MAEMOSEC_ERROR("cannot read link '%s' (%d)", pathname, errno);
				goto fail;
			} else {
				*(tgtname + rv) = '\0';
			}
			MAEMOSEC_DEBUG(1, "%s: '%s' is a link pointing to '%s'", __func__,
						   pathname, tgtname);
			if ('/' != *tgtname) {
				/*
				 * Relative link. Append its contents to the directory of the
				 * linkfile.
				 */
				const char* dirsep = strrchr(pathname, '/');
				if (dirsep) {
					dirsep++;
					if (PATH_MAX <= strlen(tgtname) + (dirsep - pathname)) {
						MAEMOSEC_ERROR("%s: too long pathname '%s' + '%s'", __func__, pathname, tgtname);
						goto fail;
					}
					memmove(tgtname + (dirsep - pathname), tgtname, strlen(tgtname) + 1);
					memcpy(tgtname, pathname, dirsep - pathname);
					MAEMOSEC_DEBUG(1, "%s: normalized relative link to '%s'", __func__, tgtname);
				}
			}
			pathname = tgtname;
			rc = lstat(pathname, &fs);
			if (rc == -1) {
				MAEMOSEC_ERROR("cannot stat '%s' (%s)", pathname, strerror(errno));
				return(false);
			}
		}

		if (!resolve_symlinks && ('/' == *pathname)) {
			to_this.assign(pathname);
			goto finish;
		}

		if (!S_ISDIR(fs.st_mode)) {
			dirsep = strrchr(pathname, '/');
			if (!dirsep) {
				dirname = ".";
				is_local = true;
			} else
				dirname.append(pathname, dirsep - pathname);
		} else
			dirname = pathname;

		if (!is_local) {
			// Take a handle to the current directory
			curdirh = open(".", O_RDONLY);
			if (curdirh == -1) {
				MAEMOSEC_ERROR("cannot open current directory (%s)", strerror(errno));
				goto fail;
			}

			// Change into the given directory
			rc = chdir(dirname.c_str());
			if (rc == -1) {
				MAEMOSEC_ERROR("cannot change into '%s' (%s)", dirname.c_str(), strerror(errno));
				goto fail;
			}
		}

		// Get the absolute pathname
		if (getcwd(cdirname, sizeof(cdirname)))
			MAEMOSEC_DEBUG(1, "current dir is '%s'", cdirname);
		else
			MAEMOSEC_ERROR("getcwd returned NULL (%s)", strerror(errno));
	
		to_this = cdirname;
		if (is_local) {
			to_this.append("/");
			to_this.append(pathname);
		} else if (dirsep) {
			to_this.append(dirsep);
		}

		if (!is_local) {
			// Change back to original working dir
			rc = fchdir(curdirh);
			if (rc == -1) {
				MAEMOSEC_ERROR("cannot change back (%s)", strerror(errno));
			}
			close(curdirh);
		}

 	finish:
		if (tgtname)
			free(tgtname);
		return(true);

	  fail:
		if (curdirh != -1) {
			if (-1 == fchdir(curdirh))
				MAEMOSEC_ERROR("Cannot cd back to original directory (%s)", strerror(errno));
			close(curdirh);
		}
		if (tgtname)
			free(tgtname);
		return(false);
	}

	bool
	process_name(string& to_this)
	{
		pid_t my_pid = getpid();
		char exe_name [PATH_MAX];

		sprintf(exe_name, "/proc/%ld/exe", (long)my_pid);
		absolute_pathname(exe_name, to_this);
		/*
		 * TODO: What follows is a somewhat ugly hack that should be 
		 * replaced by a proper application id derived from integrity 
		 * framework (i.e. package database and images hashes)
		 */
		if ("/usr/bin/maemo-launcher" == to_this) {
			int fd;
			char buf [PATH_MAX] = "";
			sprintf(exe_name, "/proc/%ld/cmdline", (long)my_pid);
			fd = open(exe_name, O_RDONLY);
			if (fd >= 0) {
				ssize_t len = read(fd, buf, sizeof(buf));
				if (len) {
					MAEMOSEC_DEBUG(1, "'%s': %ld '%s'", exe_name, len, buf);
					to_this = buf;
				}
				close(fd);
			}
		}
		return(true);
	}

	void
	append_hex(string& to_this, unsigned char* dta, unsigned len)
	{
		const unsigned locbuf_size = 128;
		char locbuf [locbuf_size + 1], *to;
		unsigned i, lim;

		lim = locbuf_size/2;
		while (len) {
			to = locbuf;
			if (lim > len)
				lim = len;
			for (i = 0; i < lim; i++) {
				sprintf(to, "%02x", *dta++);
				to += 2;
			}
			to_this.append(locbuf, i * 2);
			len -= lim;
		}
	}

	int
	file_exists(const char* name)
	{
		int rc;
		struct stat fs;

		rc = stat(name, &fs);
		if (rc == -1) {
			MAEMOSEC_DEBUG(1, "cannot stat '%s' (%s)", name, strerror(errno));
			return(0);
		}
		if (S_ISREG(fs.st_mode))
			return(1);
		else
			return(0);
	}

	int
	directory_exists(const char* name)
	{
		int rc;
		struct stat fs;

		rc = stat(name, &fs);
		if (rc == -1) {
			MAEMOSEC_DEBUG(1, "cannot stat '%s' (%s)", name, strerror(errno));
			return(0);
		}
		if (S_ISDIR(fs.st_mode))
			return(1);
		else
			return(0);
	}

	static int
	create_if_needed(const char* dir, int mode)
	{
		struct stat fs;
		int rc;
	
		MAEMOSEC_DEBUG(2, "Test '%s'", dir);
		rc = stat(dir, &fs);
		if (0 > rc) {
			if (ENOENT == errno) {
				/*
				 * Never create directories in /home when 
				 * running as root.
				 */
#define HOME "/home"
				if (0 == getuid() 
					&& strlen(dir) >= strlen(HOME) 
					&& 0 == memcmp(dir, HOME, strlen(HOME))) 
				{
					MAEMOSEC_ERROR("modifying private storage '%s' as root", dir);
					return(EACCES);
				}
#undef HOME
				MAEMOSEC_DEBUG(2, "Create '%s'", dir);
				rc = mkdir(dir, mode);
				if (0 == rc) {
					return(0);
				} else {
					MAEMOSEC_DEBUG(2, "Creation failed (%s)", 
						       strerror(errno));
					return(errno);
				}
			} else {
				MAEMOSEC_DEBUG(2, 
					       "Error other than ENOENT with '%s' (%s)", 
					       dir, strerror(errno));
				return(errno);
			}
		} else {
			if (!S_ISDIR(fs.st_mode)) {
				MAEMOSEC_DEBUG(2, "overlapping non-directory");
				return(EEXIST);
			} else
				return(0);
		}
	}

	int
	create_directory(const char* path, int mode)
	{
		string locbuf;
		char* sep;
		struct stat fs;
		int rc;

		if (!path)
			return(ENOENT);

		locbuf.assign(path);
		sep = (char*)locbuf.c_str();
		sep++;
	
		while (sep && *sep) {
			sep = strchr(sep, *PATH_SEP);
			if (sep) {
				*sep = '\0';
				rc = create_if_needed(locbuf.c_str(), mode);
				if (0 != rc) {
					MAEMOSEC_ERROR("creation of '%s' failed (%s)",
						  locbuf.c_str(), strerror(errno));
					return(errno);
				}
				*sep = *PATH_SEP;
				sep++;
			}
		}
		rc = create_if_needed(path, mode);
		if (0 != rc) {
			MAEMOSEC_ERROR("creation of '%s' failed (%s)",
				  locbuf.c_str(), strerror(errno));
			return(rc);
		} else
			return(0);
	}

	int
	iterate_files(const char* in_directory,
				  const char* matching_names,
				  maemosec_callback* cb_func,
				  void* ctx)
	{
		DIR* dh;
		unsigned char dir_d_type = '\0';
		struct dirent* entry;
		int rc, res = 0, count = 0;
		regex_t name_pattern;
		char ebuf[100];

		if (!cb_func || !in_directory)
			return(0 - EINVAL);

		if (matching_names) {
			rc = regcomp(&name_pattern, matching_names, REG_NOSUB);
			if (0 != rc) {
				res = regerror(rc, &name_pattern, ebuf, sizeof(ebuf));
				MAEMOSEC_ERROR("'%s' invalid regex %s (%d)", matching_names, ebuf, res);
				regfree(&name_pattern);
				return(0 - EINVAL);
			}
		}

		dh = opendir(in_directory);
		if (NULL == dh) {
			MAEMOSEC_ERROR("cannot open '%s'", in_directory);
			return(0 - errno);
		}
	
		while (NULL != (entry = readdir(dh))) {
			/*
			 * The first entry should always be the reference to
			 * the directory itself. From that we get the d_type
			 * value for directories. Don't want to fix it, as 
			 * man readdir says that it varies.
			 */
			MAEMOSEC_DEBUG(2, "%s:%s", __func__, entry->d_name);

			if (0 == strcmp(".", entry->d_name)
				|| 0 == strcmp("..", entry->d_name)) 
			{
				dir_d_type = entry->d_type;
				MAEMOSEC_DEBUG(2, "Directory type is '%hd'", dir_d_type);

			} else
#if 0
				if (entry->d_type != dir_d_type) {
#else
			{
#endif
				if (matching_names) {
					rc = regexec(&name_pattern, entry->d_name, 0, NULL, 0);
					MAEMOSEC_DEBUG(2, "'%s' %s '%s'", 
								   entry->d_name,  
								   rc?"!~":"~",
								   matching_names);
				} else
					rc = 0;
				if (0 == rc) {
					res = cb_func(count, entry->d_name, ctx);
					if (res)
						break;
					count++;
				}
			}
#if 0
			else {
				MAEMOSEC_DEBUG(2, "%s is directory (%hd)", entry->d_name, entry->d_type);
			}
#endif
		}
		closedir(dh);
		if (matching_names)
			regfree(&name_pattern);
		return(res);
	}

	const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

	char*
	base64_encode(unsigned char* data, unsigned len)
	{
		unsigned char* b;
		unsigned alen;
		char *res = NULL;
		char *c;
		int bytes_left = (int)len;

		alen = 4*(len/3);
		if (0 < (len%3))
			alen += 4;
		alen++;
		c = res = (char*)malloc(alen);
		
		MAEMOSEC_DEBUG(1, "%s: allocated %d bytes for %d", __func__, alen, len);
		for (b = data; 0 < bytes_left; b += 3, bytes_left -= 3) {
			/*
			 * Make four 6-bit bytes out of three 8-bit 
			 * bytes, and use them as indexes in the b64t table.
			 */
			switch (bytes_left) 
				{
				case 1:
					*c++ = b64t[(*b & 0xfc) >> 2];
					*c++ = b64t[(*b & 0x03) << 4];
					*c++ = '=';
					*c++ = '=';
					break;
				case 2:
					*c++ = b64t[(*b & 0xfc) >> 2];
					*c++ = b64t[((*b & 0x03)) << 4 | ((*(b + 1) & 0xf0) >> 4)];
					*c++ = b64t[(*(b + 1) & 0x0f) << 2];
					*c++ = '=';
					break;
				default:
					*c++ = b64t[(*b & 0xfc) >> 2];
					*c++ = b64t[((*b & 0x03) << 4) | ((*(b + 1) & 0xf0) >> 4)];
					*c++ = b64t[((*(b + 1) & 0x0f) << 2) | ((*(b + 2) & 0xc0) >> 6)];
					*c++ = b64t[*(b + 2) & 0x3f];
					break;
				}
		}
		*c = '\0';
		return(res);
	}

	unsigned
	base64_decode(char* string, unsigned char** to_buf)
	{
		char *c, *t;
		char s[4];
		unsigned len, i, done = 0;
		unsigned char *b;
		char* tbuf = NULL;

		*to_buf = NULL;
		if (NULL == string)
			return(0);

		for (len = 0, c = string; *c; c++)
			if (!isspace(*c))
				len++;

		tbuf = (char*) malloc(len + 1);
		for (t = tbuf, c = string; *c; c++)
			if (!isspace(*c))
				*t++ = *c;

		*t = '\0';
		len = len * 3;
		if (len % 4) {
			free(tbuf);
			MAEMOSEC_ERROR("Invalid base64 string (%d !%% 4)", len);
			return(0);
		}
		len >>= 2;
		MAEMOSEC_DEBUG(1, "%s: allocate %d bytes", __func__, len);
		*to_buf = b = (unsigned char*)malloc(len);

		for (c = tbuf; *c && 0 == done; c += 4) {
			/*
			 * Convert characters back to their index in the  
			 * b64t-table.
			 */
			memcpy(s, c, 4);
			for (i = 0; i < 4; i++) {
				if ('a' <= s[i] && 'z' >= s[i])
					s[i] = 26 + s[i] - 'a';
				else if ('A' <= s[i] && 'Z' >= s[i])
					s[i] = s[i] - 'A';
				else if ('0' <= s[i] && '9' >= s[i])
					s[i] = 52 + s[i] - '0';
				else if ('+' == s[i])
					s[i] = 62;
				else if ('/' == s[i])
					s[i] = 63;
				else if ('=' == s[i]) {
					s[i] = 0;
					if (3 == i) {
						len -= 1;
						done = 1;
					} else if (2 == i) {
						len -= 2;
						done = 1;
						break;
					} else {
						goto error;
					}
				} else {
				error:
					free(tbuf);
					free(*to_buf);
					*to_buf = NULL;
					MAEMOSEC_ERROR("Invalid base64 string");
					return(0);
				}
			}
			/*
			 * Restore the three original 8-bit bytes
			 * out of the four 6-bit bytes in s[4]
			 */
			*b++ = (s[0] << 2) | ((s[1] & 0x30) >> 4);
			*b++ = ((s[1] & 0x0f) << 4) | ((s[2] & 0x3c) >> 2);
			*b++ = ((s[2] & 0x03) << 6) | (s[3]);
		}
		MAEMOSEC_DEBUG(1, "%s: filled %d bytes", __func__, b - *to_buf);
		free(tbuf);
		return(len);
	}

} // extern "C"
