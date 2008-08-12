/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_config.h
 * \brief Configuration for the certman library
 */

#ifndef NGCM_CONFIG_H
#define NGCM_CONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libcertman.h>
#include "ngcm_cryptoki.h"

	CK_RV read_config(CK_ULONG* nrof_slots, 
					  CK_SLOT_ID_PTR slot_list,
					  CK_ULONG max_slots);

	CK_RV get_slot_info(CK_SLOT_ID slotID,
						CK_SLOT_INFO_PTR pInfo);
	
	CK_RV get_token_info(CK_SLOT_ID slotID,
						 CK_TOKEN_INFO_PTR pInfo);

	typedef struct session {
		CK_SESSION_HANDLE session_id;
		CK_SLOT_ID slot;
		CK_ATTRIBUTE_PTR find_template;
		CK_ULONG find_count;
		domain_handle cmdomain;
		void* certs;
		int find_point;
		int state;
		int read_only;
	} *SESSION;

	typedef enum {sstat_base, sstat_search} session_state;

	CK_SESSION_HANDLE open_session(CK_SLOT_ID slot_id);
	SESSION find_session(CK_SESSION_HANDLE sess_id);
	CK_RV close_session(CK_SESSION_HANDLE sess_id);
	CK_RV close_all_sessions(CK_SLOT_ID slot_id);

	CK_ULONG nbrof_certs(CK_SLOT_ID slotID);
	X509* get_cert(SESSION sess, int ord_nbr);

#ifdef	__cplusplus
} // extern "C"
#endif

#endif

