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

#include "ngcm_cryptoki.h"

	extern CK_RV read_config(CK_ULONG* nrof_slots, 
							 CK_SLOT_ID_PTR slot_list,
							 CK_ULONG max_slots);

	extern CK_RV get_slot_info(CK_SLOT_ID slotID,
							   CK_SLOT_INFO_PTR pInfo);

	extern CK_RV get_token_info(CK_SLOT_ID slotID,
								CK_TOKEN_INFO_PTR pInfo);
	

#ifdef	__cplusplus
} // extern "C"
#endif

#endif

