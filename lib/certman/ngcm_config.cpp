/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_config.cpp
 * \brief Configuration for the certman library
 */

#include "ngcm_config.h"
#include <sec_common.h>
#include "c_xmldoc.h"

#include <string>
#include <vector>

typedef struct int_slot_info {
	int nr;
	string label;
	string domain;
	bool is_shared;
	bool is_writable;
}* I_SLOT_INFO;

static vector<I_SLOT_INFO> slots;

extern "C" {

	const char config_file_name[] = "/etc/ngcm_cryptoki.conf";

	static void
	strbcpy(CK_UTF8CHAR* to, const char* from, const unsigned blen)
	{
		int slen = strlen(from);
		if (slen < blen) {
			memcpy((char*)to, from, slen);
			memset((char*)to + slen, ' ', blen - slen);
		} else {
			memcpy((char*)to, from, blen);
		}
		// This is not necessary
		// *(to + blen - 1) = '\0';
	}

	CK_RV 
	read_config(CK_ULONG* nrof_slots, 
				CK_SLOT_ID_PTR slot_list,
				CK_ULONG max_slots)
	{
		c_xmldoc cfile;
		c_xmlnode* cnode;
		string cfilename;
		string appname;

		absolute_pathname(GETENV("_",""), appname);
		DEBUG(0, "Init PKCS11 for '%s'", appname.c_str());
		cfile.parse_file(config_file_name);
		cnode = cfile.root();
		if (!cnode) {
			*nrof_slots = 0;
			goto end;
		}
		for (int i = 0; i < cnode->nbrof_children(); i++) {
			if ("application" == string(cnode->child(i)->name())
				&& appname == string(cnode->child(i)->attribute("path", true, ""))) 
			{
				DEBUG(0, "Found config for this application");
				cnode = cnode->child(i);
				for (int j = 0; j < cnode->nbrof_children(); j++) {
					if ("slot" == string(cnode->child(j)->name())) {
						c_xmlnode* lnode = cnode->child(j);
						I_SLOT_INFO islot = new(struct int_slot_info);
						islot->nr = atoi(lnode->attribute("nbr", true, ""));
						islot->label = lnode->attribute("label", false, "");
						islot->domain = lnode->attribute("domain", false, "");
						islot->is_shared = 
							("shared" == lnode->attribute("type",true,""));
						islot->is_writable = 
							("y" == lnode->attribute("writable",true,""));
						slots.push_back(islot);

						if (slots.size() == max_slots) {
							DEBUG(0, "All slots filled");
							goto done;
						}
					}
				}
				DEBUG(0, "found %d slots for this application", slots.size());
				break;
			}
		}
	done:		
		*nrof_slots = slots.size();
		for (int i = 0; i < slots.size(); i++) {
			slot_list[i] = slots[i]->nr;
			DEBUG(0, "Slot %d=%d", i, slot_list[i]);
		}
	end:
		return(CKR_OK);
	}

	extern CK_RV get_slot_info(CK_SLOT_ID slotID,
							   CK_SLOT_INFO_PTR pInfo)
	{
		I_SLOT_INFO sinfo = NULL;

		DEBUG(0, "%d", slotID);
		for (int i = 0; i < slots.size(); i++) {
			if (slots[i]->nr == slotID) {
				sinfo = slots[i];
				break;
			}
		}
		if (sinfo && pInfo) {
			strbcpy(pInfo->slotDescription,
					"Maemo secure certificate store",
					sizeof(pInfo->slotDescription));
			strbcpy(pInfo->manufacturerID, 
					"Nokia corporation",
					sizeof(pInfo->manufacturerID));
			pInfo->flags = CKF_TOKEN_PRESENT;
			pInfo->hardwareVersion.major = 0;
			pInfo->hardwareVersion.minor = 1;
			pInfo->firmwareVersion.major = 0;
			pInfo->firmwareVersion.minor = 1;
			return(CKR_OK);
		} else
			return(CKR_ARGUMENTS_BAD);
	}

	extern CK_RV get_token_info(CK_SLOT_ID slotID,
								CK_TOKEN_INFO_PTR pInfo)
	{
		I_SLOT_INFO sinfo = NULL;

		DEBUG(0, "%d", slotID);
		for (int i = 0; i < slots.size(); i++) {
			if (slots[i]->nr == slotID) {
				sinfo = slots[i];
				break;
			}
		}
		if (sinfo && pInfo) {
			strbcpy(pInfo->label,
					sinfo->label.c_str(),
					sizeof(pInfo->label));
			strbcpy(pInfo->manufacturerID, 
					"Nokia corporation",
					sizeof(pInfo->manufacturerID));
			strbcpy(pInfo->model, 
					"certman",
					sizeof(pInfo->model));
			strbcpy(pInfo->serialNumber, 
					"0000000000000000",
					sizeof(pInfo->serialNumber));
			pInfo->flags = CKF_TOKEN_INITIALIZED;
			if (!sinfo->is_writable) {
				pInfo->flags |= CKF_WRITE_PROTECTED;
				pInfo->ulMaxRwSessionCount = 0;
			} else
				pInfo->ulMaxRwSessionCount = 1;
			pInfo->ulMaxSessionCount = 1;
			pInfo->ulSessionCount = 1;
			pInfo->ulRwSessionCount = 0;
			pInfo->ulMaxPinLen = 0;
			pInfo->ulMinPinLen = 0;
			pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->hardwareVersion.major = 0;
			pInfo->hardwareVersion.minor = 1;
			pInfo->firmwareVersion.major = 0;
			pInfo->firmwareVersion.minor = 1;
			strncpy((char*)pInfo->utcTime, 
					"                ",
					sizeof(pInfo->utcTime));
			return(CKR_OK);
		} else
			return(CKR_ARGUMENTS_BAD);
	}
} // extern C
