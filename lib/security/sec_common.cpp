/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include "sec_common.h"

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

	if ('\0' == *pathname)
		return(false);

	rc = stat(pathname, &fs);
	if (rc == -1) {
		ERROR("cannot stat '%s' (%d)", pathname, errno);
		return(false);
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
			return(false);
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

	return(true);

fail:
	if (curdirh) {
		fchdir(curdirh);
		close(curdirh);
	}
	return(false);
}

}
