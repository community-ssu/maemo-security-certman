/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_cryptoki.c
 * \brief The PKCS#11 implementation on the certificate manager
 */

#include "ngcm_cryptoki.h"

#include <stdio.h>
#include <string.h>
#include <sec_common.h>
#include "ngcm_config.h"

static const CK_INFO library_info = {
	.cryptokiVersion = {
		.major = CRYPTOKI_VERSION_MAJOR,
		.minor = CRYPTOKI_VERSION_MINOR
	},
	.manufacturerID =
		"Nokia Corporation               ",
	.flags = 0,
	.libraryDescription =
		"maemo certificate manager       ",
	.libraryVersion = {
		.major = 0,
		.minor = 1
	},
};

/* Slot information and status */
static CK_SLOT_INFO slot_info = {
	.slotDescription =
		"maemo certman                   "
		"                                ",
	.manufacturerID =
		"Nokia Corporation               ",
	.flags = CKF_TOKEN_PRESENT,
	.hardwareVersion = {
		.major = 0,
		.minor = 1
	},
	.firmwareVersion = {
		.major = 0,
		.minor = 1
	},
};

/* Token information and status */
static CK_TOKEN_INFO token_info = {
	.label =
		"maemo certman token #1          ",
	.manufacturerID =
		"Nokia Corporation               ",
	.model =
		"certman 1.0     ",
	.serialNumber =
		"0000000000000000",
	.flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED,
	.ulMaxSessionCount = 1,
	.ulSessionCount = 0,
	.ulMaxRwSessionCount = 0,
	.ulRwSessionCount = 0,
	.ulMaxPinLen = 0,
	.ulMinPinLen = 0,
	.ulTotalPublicMemory =
		CK_UNAVAILABLE_INFORMATION,
	.ulFreePublicMemory =
		CK_UNAVAILABLE_INFORMATION,
	.ulTotalPrivateMemory =
		CK_UNAVAILABLE_INFORMATION,
	.ulFreePrivateMemory =
		CK_UNAVAILABLE_INFORMATION,
	.hardwareVersion = {
		.major = 0,
		.minor = 1
	},
	.firmwareVersion = {
		.major = 0,
		.minor = 1,
	},
	.utcTime =
		"                ",
};


static const CK_FUNCTION_LIST function_list = {
	.version = {
		.major = CRYPTOKI_VERSION_MAJOR,
		.minor = CRYPTOKI_VERSION_MINOR
	},
	#undef CK_NEED_ARG_LIST
	#define CK_PKCS11_FUNCTION_INFO(name) \
		.name = name,
#ifdef ALL_FUNCTIONS
	#include "pkcs11f.h"
#else
/* C_Initialize initializes the Cryptoki library. */
CK_PKCS11_FUNCTION_INFO(C_Initialize)
#ifdef CK_NEED_ARG_LIST
(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced */
);
#endif


/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_PKCS11_FUNCTION_INFO(C_Finalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);
#endif


/* C_GetInfo returns general information about Cryptoki. */
CK_PKCS11_FUNCTION_INFO(C_GetInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_INFO_PTR   pInfo  /* location that receives information */
);
#endif


/* C_GetFunctionList returns the function list. */
CK_PKCS11_FUNCTION_INFO(C_GetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
);
#endif



/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_PKCS11_FUNCTION_INFO(C_GetSlotList)
#ifdef CK_NEED_ARG_LIST
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
);
#endif


/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
CK_PKCS11_FUNCTION_INFO(C_GetSlotInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
);
#endif


/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
CK_PKCS11_FUNCTION_INFO(C_GetTokenInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
);
#endif


/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
CK_PKCS11_FUNCTION_INFO(C_GetMechanismList)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
);
#endif


/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
CK_PKCS11_FUNCTION_INFO(C_GetMechanismInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
);
#endif


/* C_InitToken initializes a token. */
CK_PKCS11_FUNCTION_INFO(C_InitToken)
#ifdef CK_NEED_ARG_LIST
/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
);
#endif
CK_PKCS11_FUNCTION_INFO(C_OpenSession)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
);
#endif


/* C_CloseSession closes a session between an application and a
 * token. */
CK_PKCS11_FUNCTION_INFO(C_CloseSession)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);
#endif


/* C_CloseAllSessions closes all sessions with a token. */
CK_PKCS11_FUNCTION_INFO(C_CloseAllSessions)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID     slotID  /* the token's slot */
);
#endif


/* C_GetSessionInfo obtains information about the session. */
CK_PKCS11_FUNCTION_INFO(C_GetSessionInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
);
#endif
CK_PKCS11_FUNCTION_INFO(C_CreateObject)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
);
#endif


/* C_CopyObject copies an object, creating a new object for the
 * copy. */
CK_PKCS11_FUNCTION_INFO(C_CopyObject)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
);
#endif


/* C_DestroyObject destroys an object. */
CK_PKCS11_FUNCTION_INFO(C_DestroyObject)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
);
#endif


/* C_GetObjectSize gets the size of an object in bytes. */
CK_PKCS11_FUNCTION_INFO(C_GetObjectSize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
);
#endif


/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
CK_PKCS11_FUNCTION_INFO(C_GetAttributeValue)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
);
#endif


/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
CK_PKCS11_FUNCTION_INFO(C_SetAttributeValue)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
);
#endif


/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_PKCS11_FUNCTION_INFO(C_FindObjectsInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
);
#endif


/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_PKCS11_FUNCTION_INFO(C_FindObjects)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
);
#endif


/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_PKCS11_FUNCTION_INFO(C_FindObjectsFinal)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);
#endif
#endif
	#undef CK_PKCS11_FUNCTION_INFO
};

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	DEBUG(0, "enter");
	get_config();
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	CK_RV rv;
	DEBUG(0, "enter");
	memcpy(pInfo, &library_info, sizeof(*pInfo));
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(
	CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	DEBUG(0, "enter");
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = (CK_FUNCTION_LIST_PTR)&function_list;
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_RV rv;
	CK_ULONG count = 1;

	DEBUG(0, "enter");

	/*
	 * TODO: A lot
	 */
	if (!pulCount) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	if (!pSlotList) {
		*pulCount = count;
		return CKR_OK;
	}

	if (*pulCount < count) {
		*pulCount = count;
		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = count;

	if (count > 0)
		pSlotList[0] = 1703;

	DEBUG(0, "exit");
	return CKR_OK;

  out:
	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	DEBUG(0, "enter");
	if (!pInfo) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	memcpy(pInfo, &slot_info, sizeof(*pInfo));
	DEBUG(0, "exit");
out:
	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	DEBUG(0, "enter");
	if (!pInfo) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	memcpy(pInfo, &token_info, sizeof(*pInfo));
	DEBUG(0, "exit");
out:
	return rv;
}
	
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;

	DEBUG(0, "enter");
	if (!pulCount) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	/*
	 * Don't support any mechanisms
	 */
	*pulCount = 0;
 out:
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
	CK_VOID_PTR pApplication, CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_OK;

	DEBUG(0, "enter app=%p, notify=%p", pApplication, Notify);
	if (!phSession) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	*phSession = 0;
	DEBUG(0, "exit");
	return CKR_OK;
 out:
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_OK;
}


CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phObject)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject, CK_ULONG_PTR pulSize)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	DEBUG(0, "enter %d %d %p %d", hSession, hObject, pTemplate, ulCount);
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount)
{
	DEBUG(0, "enter");
	DEBUG(0, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * TODO: better session handling
 */

static CK_ATTRIBUTE_PTR find_template = NULL;
static CK_ULONG         find_count = 0;

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	DEBUG(0, "enter %d %p %d", hSession, pTemplate, ulCount);
	find_template = pTemplate;
	find_count = ulCount;
	DEBUG(0, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv = CKR_OK;
	DEBUG(0, "enter");

	if (!find_template) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
		
	if (find_template->type == CKA_CERTIFICATE_TYPE) {
	} else {
	}
	*pulObjectCount = 0;
	DEBUG(0, "exit");
  out:
	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	DEBUG(0, "enter");
	find_template = NULL;
	DEBUG(0, "exit");
	return CKR_OK;
}

#ifdef ALL_FUNCTIONS
CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewLen)
{
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	return CKR_STATE_UNSAVEABLE;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
	CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
	CK_ULONG_PTR pulEncryptedDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
	CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
	CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
	CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
	CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags,
	CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
#endif
