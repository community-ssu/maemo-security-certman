/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_config.cpp
 * \brief Configuration for the certman library
 */

#include "ngcm_config.h"
#include <sec_common.h>
#include <c_xmldoc.h>

extern "C" {

	const char config_file_name[] = "/etc/ngcm_cryptoki.conf";

	int
	get_config(void)
	{
		DEBUG(0, "enter");
#if 1
		c_xmldoc cfile;
		string cfilename;

		cfile.parse_file(config_file_name);
		DEBUG(0, "Root: %p", (void*)cfile.root());
#endif
		DEBUG(0, "exit");
		return(0);
	}

} // extern C
