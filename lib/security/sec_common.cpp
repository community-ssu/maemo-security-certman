/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include "sec_common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

extern "C" {

	int debug_level = 0;


	void
	print_openssl_errors(void)
	{
		unsigned long l;
		const char* file;
		const char* data;
		int line, flags;
		char buf[256];
		
		while ((l = ERR_get_error_line_data(&file,&line,&data,&flags)) != 0) 
			{
				ERR_error_string_n(l, buf, sizeof(buf));
				fprintf(stderr, "%s(%d):%s:%s\n", file, line, buf,
						(flags & ERR_TXT_STRING) ? data : "");
			}
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
			ERROR("cannot stat '%s' (%d)", pathname, errno);
			return(false);
		}

		if (S_ISLNK(fs.st_mode)) {
			tgtname = (char*)malloc(PATH_MAX);
			if (!tgtname) {
				ERROR("cannot allocate");
				goto fail;
			}
			rv = readlink(pathname, tgtname, PATH_MAX - 1);
			if (rv == -1) {
				ERROR("cannot read link '%s' (%d)", pathname, errno);
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
				ERROR("cannot open current directory (%d)", errno);
				goto fail;
			}

			// Change into the given directory
			rc = chdir(dirname.c_str());
			if (rc == -1) {
				ERROR("cannot change into '%s' (%d)", dirname.c_str(), errno);
				goto fail;
			}
		}

		// Get the absolute pathname
		getcwd(cdirname, sizeof(cdirname));
		DEBUG(1, "current dir is '%s'", cdirname);
	
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
				ERROR("cannot change back (%d)", errno);
			}
			close(curdirh);
		}

		if (tgtname)
			free(tgtname);
		return(true);

	  fail:
		if (curdirh != -1) {
			fchdir(curdirh);
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
		char exe_name [256];

		sprintf(exe_name, "/proc/%ld/exe", my_pid);
		absolute_pathname(exe_name, to_this);
		return(true);
	}

	bool 
	file_exists(const char* name)
	{
		int rc;
		struct stat fs;

		rc = stat(name, &fs);
		if (rc == -1) {
			DEBUG(1, "cannot stat '%s' (%s)", name, strerror(errno));
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
			DEBUG(1, "cannot stat '%s' (%s)", name, strerror(errno));
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
					ERROR("creation of '%s' failed (%s)",
						  locbuf.c_str(), strerror(errno));
					return(errno);
				}
				*sep = *PATH_SEP;
				sep++;
			}
		}
		rc = create_if_needed(path, mode);
		if (0 != rc) {
			ERROR("creation of '%s' failed (%s)",
				  locbuf.c_str(), strerror(errno));
			return(rc);
		} else
			return(0);
	}
}
