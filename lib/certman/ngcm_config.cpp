/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_config.cpp
 * \brief Configuration for the certman library
 */

#include "ngcm_config.h"
#include <sec_common.h>
#include <c_xmldoc.h>

extern "C" {

int
get_config(void)
{
	DEBUG(0, "enter");
#if 1
	c_xmldoc cfile;
	string cfilename;

	absolute_pathname("/etc/ngcm_cryptoki.conf", cfilename);
	DEBUG(0, "Conf file: %s", cfilename.c_str());
	cfile.parse_file(cfilename.c_str());
	DEBUG(0, "Root: %p", (void*)cfile.root());
#endif
	DEBUG(0, "exit");
	return(0);
}

} // extern C
