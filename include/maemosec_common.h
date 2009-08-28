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
  
  \file maemosec_common.h
  \brief NGSW Security common definitions
  
  \mainpage NGSW Security
  
  The NGSW Security software consists of a set of security related
  libraries and binaries for the Linux-based NGSW environment of 
  Nokia devices. It contains currently the following parts:
  
  - Application launcher
  The system daemon to start processes with proper userid and group 
   membership to implement discretionary access control
  
  - Certificate management
  The certificate management library
  
  - Protected storage
  The secure storage library to protect sensitive data by encrypting
  and signing

 Copyright (c) Nokia Devices 2008
 (Licencing details to be added)

  \defgroup libcertman  Certificate management
  \defgroup sec_storage Protected storage

*/

#ifndef SEC_COMMON_H
#define SEC_COMMON_H

#include <sys/types.h>
#include <unistd.h>

#ifndef MAEMOSEC_DEBUG_ENABLED
#include <syslog.h>
#endif

#ifdef	__cplusplus
#include <string>

extern "C" {

	/**
	 * \brief Find out the absolute pathname of a file or directory
	 * \param name (in) The name of the file or directory
	 * \param to_this (out) The absolute pathname of the file or directory
	 * \returns true if the file or directory was found and was accessible,
	 * otherwise false
	 */
	bool absolute_pathname(const char* name, std::string& to_this);
	bool process_name(std::string& to_this);
	void append_hex(std::string& to_this, unsigned char* dta, unsigned len);
	
#else
	/**
	 * \def bool
	 * \brief In C-environment, define 'bool' as 'int'
	 */
	 #define bool int
#endif

	/**
	 * \def PATH_SEP
	 * \brief The path separator
	 */
	#define PATH_SEP "/"

    /**
	 * \brief Test if a file exists
	 * \param name (in) filename
	 * \returns true, if the file exists and is a regular file
	 */
	bool file_exists(const char* name);

    /**
	 * \brief Test if a directory exists
	 * \param name (in) directory name
	 * \returns true, if the file exists and is a directory
	 */
	bool directory_exists(const char* name);

	/**
	 * \brief Create a new directory. Create also all missing
	 * intermediate directories in the path, if they do not 
	 * exist already
	 * \param path (in) pathname of the directory
	 * \param mode (in) access control bits of the directory
	 * \returns 0, if the directory could be created or an error
	 *          code otherwise
	 */
	int create_directory(const char* path, int mode);

	/**
	 * \brief A generic callback function type. A function of this
	 * type is called in the various iterate_*-functions in this library.
	 * \param nbr (in) The order number of the item, starting from 0
	 * \param item (in) An item in the collection. The actual type
	 * depends on the type of the collection and is documentd for each
	 * iterate-function separately.
	 * \param context (in) A generic context pointer.
	 */
	typedef int maemosec_callback(int nbr, void* item, void* context);

	/**
	 * \brief Iterate through the files in a directory
	 * \param in_directory (in) the name of the directory
	 * \param matching_names (in) a regular expression matched against
	 * the filenames
	 * \param cb_func (in) a callback function which is called for each
	 * file in the given directory that has a name matching with the
	 * given expression. The item parameter is a NUL-terminated filename.
	 * \param ctx (in) the context pointer
	 */
	int	iterate_files(const char* in_directory,
					  const char* matching_names,
					  maemosec_callback* cb_func,
					  void* ctx);

	/**
	 * \brief Send a debug or error message to the dlog
	 */
	void dlog_message(const char* format, ...);

	/**
	 * \brief Return a hex string describing given data
	 */
	const char* dynhex(const unsigned char* d, unsigned len);

	/**
	 * \brief Base-64 encode
	 */
	char* base64_encode(unsigned char* data, unsigned len);

	/**
	 * \brief Base-64 decode
	 */
	unsigned base64_decode(char* string, unsigned char** to_buf);

#ifdef	__cplusplus
} // extern "C"
#endif

#ifndef _STRING_H
#include <string.h>
#endif

/**
 * \def bare_file_name
 * \brief Return the file name part of a pathname
 * \param s a path name
 */
#define bare_file_name(s) strrchr(s,'/')?strrchr(s,'/')+1:s

/**
 * \def MAEMOSEC_ERROR
 * \brief Report an error to the dlog server.
 * \param format,args Format string and a list of optional arguments
 * as in "printf".
 */
#ifdef MAEMOSEC_DEBUG_ENABLED
#define MAEMOSEC_ERROR(format,args...) \
	do {\
	  dlog_message("<0>%s(%d)[%d]: ERROR " format, bare_file_name(__FILE__), __LINE__, \
					 getpid() ,##args);\
	} while (0)
#else
#define MAEMOSEC_ERROR(format,args...) \
	do {\
		syslog(LOG_ERR, "%s(%d): ERROR " format, bare_file_name(__FILE__), __LINE__ ,##args);\
	} while (0)
#endif

/**
 * \def MAEMOSEC_DEBUG
 * \brief Send a debug message to the dlog server.
 * \param level (in) The detail level. Only those messages are actually
 * printed thatb have the detail level less than or equal than the
 * current value of the debug_level variable.
 * \param format,args (in) Format string and a list of optional arguments
 * as in "printf".
 */
#ifdef MAEMOSEC_DEBUG_ENABLED
#define MAEMOSEC_DEBUG(level,format,args...)	\
	do { \
	  dlog_message("<%d>%s(%d)[%d]: " format, level, bare_file_name(__FILE__), __LINE__, \
					 getpid() ,##args);							\
    } while (0)
#else
#define MAEMOSEC_DEBUG(level,format,args...)
#endif

/**
 * \def GETENV
 * \brief Get environment value or the default if not found
 * \param name of the environment variable 
 * \param deflt of the environment variable 
 */
#define GETENV(name,deflt) ({char* c = getenv(name); c?c:deflt;})

#endif
