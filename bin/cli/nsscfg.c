// -*- mode:c; tab-width:4; c-basic-offset:4; -*-
#include <stdio.h>
#include <nss.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>
#include <cert.h>
#include <secmod.h>
#include <p12.h>
#include <certdb.h>
#include <maemosec_common.h>

#define DEFAULT_CFG_DIR  "/home/user/.netscape"
#define DEFAULT_DLL_NAME "/usr/lib/libmaemosec_certman.so.0.0.0"
#define DEFAULT_MOD_NAME "maemo-security-certman"
#define NSS_FLAGS        "trustOrder=70 \
 slotParams=0x6a5=[slotFlags=PublicCerts,rootFlags]"

static char cfg_dir  [PATH_MAX] = DEFAULT_CFG_DIR;
static char mod_name [PATH_MAX] = DEFAULT_MOD_NAME;
static char dll_name [PATH_MAX] = DEFAULT_DLL_NAME;

enum {
	mode_update, 
	mode_info, 
	mode_remove, 
	mode_remove_internal,
	mode_export
} op_mode = mode_update;

static int ccount = 0;

static void
usage(void)
{
	printf("%s\n", "Usage: nsscfg -c config-dir [-m module] [-l library]");
}

static SECStatus
count_certs(CERTCertificate* cert, SECItem *k, void *pdata)
{
	ccount++;
	return(SECSuccess);
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
		a = getopt(argc, argv, "c:m:l:ir:Re");
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
			case 'i':
				op_mode = mode_info;
				break;
			case 'r':
				op_mode = mode_remove;
				strncpy(mod_name, optarg, sizeof(mod_name));
				break;
			case 'R':
				op_mode = mode_remove_internal;
				break;
			case 'e':
				op_mode = mode_export;
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

	if (mode_update == op_mode) {
		mod = SECMOD_FindModule(mod_name);
		if (mod) {
			MAEMOSEC_DEBUG(1, "Updating '%s'", mod_name);
			mod->dllName = dll_name;
			rv = SECMOD_UpdateModule(mod);
			MAEMOSEC_DEBUG(1, "SECMOD_UpdateModule returned %d", rv);
		} else {
			MAEMOSEC_DEBUG(1, "Adding '%s'", mod_name);
			rv = SECMOD_AddNewModuleEx(mod_name, dll_name, 0, 0, NULL, NSS_FLAGS);
			MAEMOSEC_DEBUG(1, "SECMOD_AddNewModuleEx returned %d", rv);
		}
		if (SECSuccess == rv)
			printf("Added %s in %s\n", mod_name, cfg_dir);
		else
			printf("ERROR: %d in adding %s to %s\n", rv, mod_name, cfg_dir);

	} else if (mode_info == op_mode) {
		SECMODModuleList* m_list = SECMOD_GetDefaultModuleList();
		while (m_list) {
			if (m_list->module) {
				printf("Module: %s\nLibrary: %s\nisCritical=%s\nisModuleDB=%s\n"
					   "moduleDBOnly=%s\ntrustOrder=%d\n",
					   m_list->module->commonName,
					   m_list->module->dllName,
					   m_list->module->isCritical?"yes":"no",
					   m_list->module->isModuleDB?"yes":"no",
					   m_list->module->moduleDBOnly?"yes":"no",
					   m_list->module->trustOrder
					   );
			}
			if (m_list->next) {
				printf("\n");
				m_list = m_list->next;
			} else
				break;
		}

	} else if (mode_remove == op_mode) {
		int type = 0;
		rv = SECMOD_DeleteModule(mod_name, &type);
		if (SECSuccess == rv)
			printf("Removed '%s'\n", mod_name);
		else
			fprintf(stderr, "ERROR: Cannot remove '%s' (%d)\n", mod_name, rv);

	} else if (mode_remove_internal == op_mode) {
		if (SECMOD_CanDeleteInternalModule()) {
			mod = SECMOD_GetInternalModule();
			if (mod && mod->commonName) {
				rv = SECMOD_DeleteInternalModule(mod->commonName);
				if (SECSuccess == rv)
					printf("Removed internal module '%s'\n", mod->commonName);
				else
					fprintf(stderr, "ERROR: Cannot remove internal module '%s' (%d)\n", 
							mod->commonName, rv);
			} else
				fprintf(stderr, "ERROR: No internal module exists\n");
		} else
			fprintf(stderr, "ERROR: Cannot delete internal module (no permission)\n");

	} else if (mode_export == op_mode) {
		CERTCertDBHandle *dbh;
		rv = SEC_OpenPermCertDB(&dbh, 1, NULL, NULL);
		if (SECSuccess != rv) {
			fprintf(stderr, "ERROR: cannot open cert db (%d)\n", rv);
			goto shutdown;
		}

		rv = PCERT_TraversePermCerts(dbh, count_certs, NULL);
		if (SECSuccess != rv) {
			fprintf(stderr, "ERROR: failed to traverse database (%d)\n", rv);
		}

		/*
		 * TODO: Close the handle. Do not know which function?
		 */

	}
		
 shutdown:
	rv = NSS_Shutdown();
	MAEMOSEC_DEBUG(1, "NSS_Shutdown returned %d", rv);

	return(0);
}
