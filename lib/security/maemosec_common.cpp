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

extern "C" {

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
			MAEMOSEC_ERROR("cannot stat '%s' (%d)", pathname, errno);
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
			pathname = tgtname;
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
				MAEMOSEC_ERROR("cannot open current directory (%d)", errno);
				goto fail;
			}

			// Change into the given directory
			rc = chdir(dirname.c_str());
			if (rc == -1) {
				MAEMOSEC_ERROR("cannot change into '%s' (%d)", dirname.c_str(), errno);
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
				MAEMOSEC_ERROR("cannot change back (%d)", errno);
			}
			close(curdirh);
		}

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

	bool 
	file_exists(const char* name)
	{
		int rc;
		struct stat fs;

		rc = stat(name, &fs);
		if (rc == -1) {
			MAEMOSEC_DEBUG(1, "cannot stat '%s' (%s)", name, strerror(errno));
			return(false);
		}
		if (S_ISREG(fs.st_mode))
			return(true);
		else
			return(false);
	}

	bool 
	directory_exists(const char* name)
	{
		int rc;
		struct stat fs;

		rc = stat(name, &fs);
		if (rc == -1) {
			MAEMOSEC_DEBUG(1, "cannot stat '%s' (%s)", name, strerror(errno));
			return(false);
		}
		if (S_ISDIR(fs.st_mode))
			return(true);
		else
			return(false);
	}

	static int
	create_if_needed(const char* dir, int mode)
	{
		struct stat fs;
		int rc;
	
		MAEMOSEC_DEBUG(2, "Test '%s'", dir);
		rc = stat(dir, &fs);
		if (0 > rc) {
			if (errno == ENOENT) {
				MAEMOSEC_DEBUG(2, "Create '%s'", dir);
				rc = mkdir(dir, mode);
				if (0 > rc) {
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

}
