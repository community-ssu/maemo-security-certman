// -*- mode:c; tab-width:4; c-basic-offset:4; -*-
#include <stdio.h>
#include <nss.h>
#include <secmod.h>
#include <maemosec_common.h>

int
main(void)
{
	SECStatus rv;
	SECMODListLock* llock = NULL;
	SECMODModuleList* mlist = NULL;

	MAEMOSEC_DEBUG(1, "started");

	rv = NSS_Initialize("/var/jum/.mozilla/firefox/4rhzbuzp.minefield", "", "", "", 0);
	MAEMOSEC_DEBUG(1, "NSS_Initialize returned %d", rv);

	mlist = SECMOD_GetDBModuleList();
	if (mlist) {
		do {
			printf("Module: %s\nLibrary: %s\n", 
				   mlist->module->commonName, 
				   mlist->module->dllName);
			mlist = mlist->next;
		} while (mlist);
	} else
		MAEMOSEC_ERROR("No modules available");

	rv = NSS_Shutdown();
	MAEMOSEC_DEBUG(1, "NSS_Shutdown returned %d", rv);

	return(0);
}
