// -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/*!
  
  @file sec_common.h
  @brief NGSW Security common definitions
  
  @mainpage NGSW Security
  
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

  @defgroup applauncher Application launcher
  @defgroup libcertman  Certificate management
  @defgroup sec_storage Protected storage

*/

#ifndef SEC_COMMON_H
#define SEC_COMMON_H

#ifdef	__cplusplus
#include <string>
using namespace std;

extern "C" {
#endif

/**
 * \var debug_level
 * \brief Set this value non-zero to produce debug output
 */
extern int debug_level;

void print_openssl_errors(void);

/**
 * \brief Find out the absolute pathname of a file or directory
 * \param name (in) The name of the file or directory
 * \param to_this (out= The absolute pathname of the file or directory
 * \returns true if the file or directory was found and was accessible,
 * otherwise false
 */
bool absolute_pathname(const char* name, string& to_this);

#ifdef	__cplusplus
} // extern "C"
#endif

/**
 * \def ERROR
 * \brief Report an error 
 * \param format,args Format string and a list of optional arguments
 * as in "printf"
 */
#define ERROR(format,args...) \
	do {\
		printf("%s(%d)[%s]: ERROR " format "\n", __FILE__, __LINE__,__func__,\
			   ##args);\
	} while (0)

/**
 * \def DEBUG
 * \brief Print a debug message
 * \param level The detail level. Only those messages are actually
 * printed that have the detail level less than or equal than the
 * current value of the \ref debug_level
 * \param format,args Format string and a list of optional arguments
 * as in "printf"
 */
#define DEBUG(level,format,args...)	\
	do { \
	    if (level <= debug_level) {	\
		    printf("%s(%d)[%s]: " format "\n", __FILE__, __LINE__,__func__,\
			   ##args);\
	    } \
    } while (0)

#endif
