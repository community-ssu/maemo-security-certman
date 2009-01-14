// -*- mode:c; tab-width:4; c-basic-offset:4; -*-
#include <stdio.h>
#include <nss.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>
#include <secmod.h>
#include <maemosec_common.h>

#define DEFAULT_CFG_DIR  "/home/user/.netscape"
#define DEFAULT_DLL_NAME "/usr/lib/libmaemosec_certman.so.0.0.0"
#define DEFAULT_MOD_NAME "maemo-security-certman"

static char cfg_dir  [PATH_MAX] = DEFAULT_CFG_DIR;
static char mod_name [PATH_MAX] = DEFAULT_MOD_NAME;
static char dll_name [PATH_MAX] = DEFAULT_DLL_NAME;

static void
usage(void)
{
	printf("%s\n", "Usage: nsscfg -c config-dir [-m module] [-l library]");
}

int
main(int argc, char* argv[])
{
	SECStatus rv;
	SECMODModule* mod = NULL;
	signed char a;
	int rc;

	MAEMOSEC_DEBUG(1, "started");

	while (1) {
		a = getopt(argc, argv, "c:m:l:");
		if (0 > a)
			break;
		switch (a) 
			{
			case 'c':
				strncpy(cfg_dir, optarg, sizeof(cfg_dir));
				break;
			case 'm':
				strncpy(mod_name, optarg, sizeof(mod_name));
				break;
			case 'l':
				strncpy(dll_name, optarg, sizeof(dll_name));
				break;
			default:
				MAEMOSEC_DEBUG(1, "Invalid option '%hd'", a);
				usage();
				return(-1);
			}
	}

	MAEMOSEC_DEBUG(1, "Configure %s", cfg_dir);

	if (!directory_exists(cfg_dir)) {
		rc = create_directory(cfg_dir, 0755);
		if (0 != rc) {
			MAEMOSEC_ERROR("Could not create dir '%s' (%d)", 
						   cfg_dir, rc);
			return(-1);
		} else
			MAEMOSEC_DEBUG(1, "Created dir '%s'", cfg_dir);
	}

	rv = NSS_Initialize(cfg_dir, "", "", "", 0);
	MAEMOSEC_DEBUG(1, "NSS_Initialize returned %d", rv);
	if (SECSuccess != rv) {
		MAEMOSEC_ERROR("Failed to initialize NSS library for '%s' (%d)", 
					   cfg_dir, rv);
		return(-1);
	}

	mod = SECMOD_FindModule(mod_name);
	if (mod) {
		MAEMOSEC_DEBUG(1, "Updating '%s'", mod_name);
		mod->dllName = dll_name;
		rv = SECMOD_UpdateModule(mod);
		MAEMOSEC_DEBUG(1, "SECMOD_UpdateModule returned %d", rv);
	} else {
		MAEMOSEC_DEBUG(1, "Adding '%s'", mod_name);
		rv = SECMOD_AddNewModuleEx(mod_name, dll_name, 0, 0, NULL, 
								   "critical,moduleDBOnly");
		MAEMOSEC_DEBUG(1, "SECMOD_AddNewModuleEx returned %d", rv);
	}
	if (SECSuccess == rv)
		printf("Added %s in %s\n", mod_name, cfg_dir);
	else
		printf("ERROR: %d in adding %s to %s\n", rv, mod_name, cfg_dir);
	
	rv = NSS_Shutdown();
	MAEMOSEC_DEBUG(1, "NSS_Shutdown returned %d", rv);

	return(0);
}
