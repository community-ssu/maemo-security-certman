// -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
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
	 * \def path_sep
	 * \brief Let's not rely on even this
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

	typedef int maemosec_callback(int nbr, void* item, void* context);

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

#ifdef	__cplusplus
} // extern "C"
#endif

/**
 * \def MAEMOSEC_ERROR
 * \brief Report an error to the dlog server.
 * \param format,args Format string and a list of optional arguments
 * as in "printf".
 */
#define MAEMOSEC_ERROR(format,args...) \
	do {\
		dlog_message("<0>%s(%d)[%d]: ERROR " format, __FILE__, __LINE__, \
					 getpid() ,##args);\
	} while (0)

/**
 * \def MAEMOSEC_DEBUG
 * \brief Send a debug message to the dlog server.
 * \param level (in) The detail level. Only those messages are actually
 * printed thatb have the detail level less than or equal than the
 * current value of the debug_level variable.
 * \param format,args (in) Format string and a list of optional arguments
 * as in "printf".
 */
#define MAEMOSEC_DEBUG(level,format,args...)	\
	do { \
		dlog_message("<%d>%s(%d)[%d]: " format, level, __FILE__, __LINE__, \
					 getpid() ,##args);							\
    } while (0)

#ifdef ULOG_DEBUG
#undef ULOG_DEBUG
#define ULOG_DEBUG(args...) MAEMOSEC_DEBUG(2 ,##args)
#endif

/**
 * \def GETENV
 * \brief Get environment value or the default if not found
 * \param name of the environment variable 
 * \param deflt of the environment variable 
 */
#define GETENV(name,deflt) ({char* c = getenv(name); c?c:deflt;})

#endif
