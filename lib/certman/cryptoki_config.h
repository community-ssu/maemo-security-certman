/* -*- mode:c; tab-width:4; c-basic-offset:4; -*-
 *
 * This file is part of maemo-security-certman
 *
 * Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Juhani Mäkelä <ext-juhani.3.makela@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**
 * \file cryptoki_config.h
 * \brief Configuration for the certman library
 */

#ifndef CRYPTOKI_CONFIG_H
#define CRYPTOKI_CONFIG_H

#include <maemosec_certman.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include "cryptoki_module.h"

CK_RV read_config(CK_ULONG* nrof_slots, 
				  CK_SLOT_ID_PTR slot_list,
				  CK_ULONG max_slots);

CK_RV get_slot_info(CK_SLOT_ID slotID,
					CK_SLOT_INFO_PTR pInfo);
	
CK_RV get_token_info(CK_SLOT_ID slotID,
					 CK_TOKEN_INFO_PTR pInfo);

void release_config(void);

typedef struct session {
	CK_SESSION_HANDLE session_id;
	CK_SLOT_ID slot;
	CK_ATTRIBUTE_PTR find_template;
	CK_ULONG find_count;
	domain_handle cmdomain;
	const char* domain_name;
	void* certs;
	int find_point;
	int state;
	int read_only;
	char password [256];
	EVP_PKEY* signing_key;
	int signing_algorithm;
} *SESSION;

typedef enum {sstat_base, sstat_search} session_state;

CK_SESSION_HANDLE open_session(CK_SLOT_ID slot_id);
SESSION find_session(CK_SESSION_HANDLE sess_id);
CK_RV close_session(CK_SESSION_HANDLE sess_id);
CK_RV close_all_sessions(CK_SLOT_ID slot_id);

CK_ULONG nbrof_certs(CK_SLOT_ID slotID);
X509* get_cert(SESSION sess, int ord_nbr);
CK_RV add_cert(SESSION sess, X509* cert, int* ord_nbr);

#ifdef	__cplusplus
} // extern "C"
#endif

#endif

