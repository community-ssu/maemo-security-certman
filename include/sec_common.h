/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#ifndef SEC_COMMON_H
#define SEC_COMMON_H

#ifdef	__cplusplus
#include <string>
using namespace std;

extern "C" {
#endif

extern int debug_level;

void print_openssl_errors(void);
bool absolute_pathname(const char* dirname, string& to_this);

#ifdef	__cplusplus
} // extern "C"
#endif

// Some helper macros
#define ERROR(format,args...) \
	do {\
		printf("%s(%d)[%s]: ERROR " format "\n", __FILE__, __LINE__,__func__,\
			   ##args);\
	} while (0)

#define DEBUG(level,format,args...)	\
	if (level <= debug_level) { \
		printf("%s(%d)[%s]: " format "\n", __FILE__, __LINE__,__func__,\
			   ##args);\
	}

#endif
