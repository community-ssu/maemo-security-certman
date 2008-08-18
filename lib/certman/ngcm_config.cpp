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
	CK_SLOT_ID nr;
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

		process_name(appname);
		DEBUG(1, "Init PKCS11 for '%s'", appname.c_str());
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
				DEBUG(1, "Found config for this application");
				cnode = cnode->child(i);
				for (int j = 0; j < cnode->nbrof_children(); j++) {
					if ("slot" == string(cnode->child(j)->name())) {
						c_xmlnode* lnode = cnode->child(j);
						I_SLOT_INFO islot = new(struct int_slot_info);
						islot->nr = atoi(lnode->attribute("nbr", true, ""));
						islot->label = lnode->attribute("label", false, "");
						islot->domain = lnode->attribute("domain", false, "");
						islot->is_shared = 
							("shared" == string(lnode->attribute("type",true,"")));
						islot->is_writable = 
							("y" == string(lnode->attribute("writable",true,"")));
						slots.push_back(islot);

						if (slots.size() == max_slots) {
							DEBUG(1, "All slots filled");
							goto done;
						}
					}
				}
				DEBUG(1, "found %d slots for this application", slots.size());
				break;
			}
		}
	done:		
		*nrof_slots = slots.size();
		for (int i = 0; i < slots.size(); i++) {
			slot_list[i] = slots[i]->nr;
			DEBUG(1, "Slot %d=%d", i, slot_list[i]);
		}
	end:
		return(CKR_OK);
	}

	extern CK_RV get_slot_info(CK_SLOT_ID slotID,
							   CK_SLOT_INFO_PTR pInfo)
	{
		I_SLOT_INFO sinfo = NULL;

		DEBUG(1, "%d", slotID);
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

		DEBUG(1, "%d", slotID);
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
	
	static CK_SESSION_HANDLE last_session = 0;
	static vector<SESSION> sessions;
	typedef vector<SESSION>::iterator siter;

	CK_SESSION_HANDLE 
	open_session(CK_SLOT_ID slot_id)
	{
		SESSION new_session;
		I_SLOT_INFO slot_info = NULL;
		domain_handle domain;
		int rc;

		for (size_t i = 0; i < slots.size(); i++) {
			if (slots[i]->nr == slot_id) {
				slot_info = slots[i];
			}
		}
		if (!slot_info)
			return(CKR_SLOT_ID_INVALID);

		DEBUG(1, "open %s domain %s", 
			  slot_info->is_shared
			  ?"shared":"private",
			  slot_info->domain.c_str());
		rc = ngsw_certman_open_domain(slot_info->domain.c_str(),
									  slot_info->is_shared
									  ?NGSW_CD_COMMON:NGSW_CD_PRIVATE,
									  &domain);
		if (rc != 0) {
			return(CKR_SLOT_ID_INVALID);
		}

		new_session = new(struct session);
		memset(new_session, '\0', sizeof(struct session));
		/*
		 * Don't start from zero as zero is an invalid session handle
		 */
		new_session->session_id = ++last_session;
		new_session->slot = slot_id;
		new_session->cmdomain = domain;
		new_session->read_only = !slot_info->is_writable;
		new_session->state = sstat_base;
		sessions.push_back(new_session);
		return(new_session->session_id);
	}

	SESSION
	find_session(CK_SESSION_HANDLE sess_id)
	{
		for (size_t i = 0; i < sessions.size(); i++) {
			if (sessions[i]->session_id == sess_id)
				return(sessions[i]);
		}
		return(NULL);
	}

	typedef vector<X509*> cstore;

	static int
	cb_copy_cert(int ordnr, X509* cert, void* sh)
	{
		cstore* certs = (cstore*)sh;
		certs->push_back(cert);
		DEBUG(1, "Read certificate");
		return(-1);
	}

	X509*
	get_cert(SESSION sess, int ord_nbr)
	{
		cstore* certs;

		if (sess->certs == NULL) {
			certs = new(cstore);
			sess->certs = certs;
			ngsw_certman_iterate_domain(sess->cmdomain, 
										cb_copy_cert,
										sess->certs);
		} else {
			certs = (cstore*)sess->certs;
		}
		if (ord_nbr < certs->size()) {
			return((*certs)[(size_t)ord_nbr]);
		} else {
			ERROR("invalid object nbr %d", ord_nbr);
			return(NULL);
		}
	}

	CK_RV
	close_session(CK_SESSION_HANDLE sess_id)
	{
		for (size_t i = 0; i < sessions.size(); i++) {
			if (sessions[i]->session_id == sess_id) {
				SESSION sess = sessions[i];
				sessions.erase(sessions.begin() + i);
				if (sess->certs) {
					cstore* certs = (cstore*)sess->certs;
					for (size_t j = 0; j < certs->size(); j++) {
						X509_free((*certs)[j]);
					}
					delete(certs);
				}
				delete(sess);
				DEBUG(1, "exit, closed session %d", sess_id);
				return(CKR_OK);
			}
		}
		DEBUG(1, "exit, session_not_found");
		return(CKR_SESSION_HANDLE_INVALID);
	}

	CK_RV 
	close_all_sessions(CK_SLOT_ID slot_id)
	{
		for (size_t i = 0; i < sessions.size(); i++) {
			if (sessions[i]->slot == slot_id) {
				SESSION sess = sessions[i];
				sessions.erase(sessions.begin() + i);
				delete(sess);
			}
		}
		DEBUG(1, "closed all sessions for slot %d", slot_id);
		return(CKR_OK);
	}
} /* extern C */
