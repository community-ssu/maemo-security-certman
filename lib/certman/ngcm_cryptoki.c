/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_cryptoki.c
 * \brief The PKCS#11 implementation on the certificate manager
 */

#include "ngcm_cryptoki.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <string.h>
#include <sec_common.h>
#include <libcertman.h>
#include "ngcm_config.h"

/*
 * Include Netscape's (Mozilla's) vendor defined extensions
 */
#define INCL_NETSCAPE_VDE 1

#ifdef INCL_NETSCAPE_VDE
#define PR_CALLBACK
#include "pkcs11n.h"
#endif

static X509_STORE* root_certs;

static const char* attr_name(CK_ATTRIBUTE_TYPE of_a);


static const CK_INFO library_info = {
	.cryptokiVersion = {
		.major = CRYPTOKI_VERSION_MAJOR,
		.minor = CRYPTOKI_VERSION_MINOR
	},
	.manufacturerID =
		"Nokia Corporation               ",
	.flags = 0,
	.libraryDescription =
		"Maemo certificate manager       ",
	.libraryVersion = {
		.major = 0,
		.minor = 1
	},
};

static CK_ULONG obj_type_cert = CKO_CERTIFICATE;

static const CK_ATTRIBUTE find_certs_tpl = {
	.type = CKA_CLASS,
	.pValue = &obj_type_cert
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
	#include "pkcs11f-partial.h"
#endif
	#undef CK_PKCS11_FUNCTION_INFO
};

/*
 * Own stuff
 */

/*
 * TODO: A global session id counter; not re-entrant!
 */
static CK_ULONG nrof_slots = 0;
static CK_SLOT_ID slot_lst[10];

#define GET_SESSION(id,to_this)					\
	do {										\
		to_this = find_session(id);				\
		if (!to_this) {							\
			ERROR("session %d not found", (int)id);	\
			return(CKR_SESSION_HANDLE_INVALID);	\
		}										\
	} while (0);

/*
 * Helper functions
 */
static CK_RV
copy_attribute(const void* value, CK_ULONG size, CK_ATTRIBUTE_PTR p)
{
	CK_RV rv = CKR_OK;

	if (p->pValue) {
		if (p->ulValueLen >= size) {
			DEBUG(2, "%s", attr_name(p->type));
			memcpy(p->pValue, value, size);
		} else {
			DEBUG(1, "buf %ld cannot take %ld", p->ulValueLen, size);
			rv = CKR_BUFFER_TOO_SMALL;
		}
	}
	p->ulValueLen = size;
	return(rv);
}

static CK_RV
match_attribute(const void* value, CK_ULONG size, CK_ATTRIBUTE_PTR p)
{
	CK_RV rv;
	if (   p 
		&& p->ulValueLen == size
		&& p->pValue
		&& memcmp(p->pValue, value, size) == 0)
    {
		rv = CKR_OK;
	} else {
#ifdef INCL_NETSCAPE_VDE
		long val = *(long*)p->pValue;
		DEBUG(2, "%s(%ld,%ld) %lx(%lx) != %lx", attr_name(p->type),
			  p->ulValueLen, size, 
			  val, 
			  val >= CKO_NSS ? val - CKO_NSS : -1,
			  *(long*)value);
#endif
		rv = CKR_CANCEL;
	}
	return(rv);
}


static CK_RV
read_attribute(CK_ATTRIBUTE_PTR p, 
			   void* value, 
			   CK_ULONG max_size, 
			   CK_ULONG* real_size)
{
	if (!p
		|| !p->pValue
		|| p->ulValueLen == 0
		|| !value)
		return(CKR_ARGUMENTS_BAD);

	*real_size = p->ulValueLen;

	if (p->ulValueLen > max_size)
		return(CKR_BUFFER_TOO_SMALL);
	memcpy(value, p->pValue, p->ulValueLen);
	return(CKR_OK);
}


static CK_RV
access_attribute(SESSION sess,
				 X509* cert,
				 int cert_number,
				 CK_ATTRIBUTE_PTR attr,
				 CK_RV callback(const void* value, CK_ULONG size, CK_ATTRIBUTE_PTR p))
{
	CK_RV rv = CKR_OK;

	switch (attr->type) {
	case CKA_CLASS:
		{
			CK_OBJECT_CLASS objtype = CKO_CERTIFICATE;
			rv = callback(&objtype, sizeof(objtype), attr);
		}
		break;
	case CKA_CERTIFICATE_TYPE:
		{
			CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
			rv = callback(&cert_type, sizeof(cert_type), attr);
		}
		break;
	case CKA_VALUE:
		{
			unsigned char* obuf = NULL;
			int len;

			len = i2d_X509(cert, &obuf);
			if (len <= 0) {
				ERROR("Cannot encode cert (%d)", len);
				rv = CKR_FUNCTION_FAILED;
				goto out;
			} else {
				rv = callback(obuf, len, attr);
			}
			if (obuf) 
				OPENSSL_free(obuf);
		}
		break;
	case CKA_TRUSTED:
	case CKA_TOKEN:
	case CKA_PRIVATE:
		{
			CK_BBOOL avalue = CK_TRUE;
			rv = callback(&avalue, sizeof(avalue), attr);
		}
		break;
	case CKA_MODIFIABLE:
		{
			CK_BBOOL avalue = CK_FALSE;
			rv = callback(&avalue, sizeof(avalue), attr);
		}
		break;
	case CKA_CERTIFICATE_CATEGORY:
		{
			/*
			 * TODO: other than authority certs supported?
			 * There seems not to be any constants for this?
			 */
			CK_ULONG avalue = 2;
			rv = callback(&avalue, sizeof(avalue), attr);
		}
		break;
	case CKA_CHECK_VALUE:
		{
			/*
			 * TODO: a checksum, where should this be taken from?
			 */
			rv = callback(cert->sha1_hash, 
						  SHA_DIGEST_LENGTH, 
						  attr);
		}
		break;
	case CKA_START_DATE:
	case CKA_END_DATE:
		{
			CK_DATE avalue;
			ASN1_GENERALIZEDTIME* svalue;
			if (attr->type == CKA_START_DATE)
				svalue = X509_get_notBefore(cert);
			else
				svalue = X509_get_notAfter(cert);
			if (!svalue || svalue->length < 12) {
				rv = CKR_FUNCTION_FAILED;
				goto out;
			}
			/*
			 * TODO: UTC to local time conversion?
			 */
			memcpy(avalue.year,  &svalue->data[0], 4);
			memcpy(avalue.month, &svalue->data[4], 2);
			memcpy(avalue.day,   &svalue->data[6], 2);
			rv = callback(&avalue, sizeof(avalue), attr);
		}
		break;
#if 0
	case CKA_MODULUS_BITS:
		break;
	case CKA_MODULUS:
		break;
	case CKA_PUBLIC_EXPONENT:
		break;
	case CKA_KEY_TYPE:
		break;
	case CKA_CLASS:
		break;
#endif
	case CKA_SUBJECT:
	case CKA_ISSUER:
		{
			unsigned char* buf = NULL;
			X509_NAME* name;
			int len;
			
			switch (attr->type) {
			case CKA_SUBJECT:
				name = X509_get_subject_name(cert);
				break;
			case CKA_ISSUER:
				name = X509_get_issuer_name(cert);
				break;
			default:
				attr->ulValueLen = -1;
				goto out;
			}
			len = i2d_X509_NAME(name, &buf);
			if (len > 0) {
				rv = callback(buf, len, attr);
			} else
				rv = CKR_FUNCTION_FAILED;
			if (buf)
				OPENSSL_free(buf);
		}
		break;

	case CKA_SERIAL_NUMBER:
		{
			unsigned char* buf = NULL;
			ASN1_INTEGER* ival;
			int len;

			switch (attr->type) {
			case CKA_SERIAL_NUMBER:
				ival = X509_get_serialNumber(cert);
				break;
			default:
				rv = CKR_FUNCTION_FAILED;
				goto out;
			}
			len = i2d_ASN1_INTEGER(ival, &buf);
			if (len > 0) {
				rv = callback(buf, len, attr);
			} else
				rv = CKR_FUNCTION_FAILED;
			if (buf)
				OPENSSL_free(buf);
		}
		break;
				
	case CKA_LABEL:
		{
#if 1
			char buf[255];
			snprintf(buf, sizeof(buf), "%s#%d", 
					 sess->domain_name, 
					 cert_number);
			rv = callback(buf, strlen(buf), attr);
#else
			unsigned char* buf = NULL;
			int len = i2d_X509_NAME(X509_get_subject_name(cert), &buf);
			if (len > 0) {
				rv = callback(buf, len, attr);
			}
			if (buf)
				OPENSSL_free(buf);
#endif
		}
		break;

	case CKA_ID:
		{
			/*
			 * TODO: Guess what
			 */
			CK_ULONG cert_id = 0x1703 + cert_number;
			rv = callback(&cert_id, sizeof(cert_id), attr);
		}
		break;

	default:
		DEBUG(1, "unsupported attribute id %x", (int)attr->type);
#if 0
		if (attr->pValue)
			rv = CKR_FUNCTION_NOT_SUPPORTED;
#endif
		attr->ulValueLen = -1;
		break;
	}
 out:
	return(rv);
}


static CK_RV
set_attribute(SESSION sess,
			  X509** cert,
			  CK_ATTRIBUTE_PTR attr
) {
	CK_RV rv = CKR_OK;
	CK_ULONG val_len;

	switch (attr->type) {
	case CKA_CLASS:
		{
			CK_OBJECT_CLASS objtype;
			rv = read_attribute(attr, &objtype, sizeof(objtype), &val_len);
			if (CKR_OK == rv && CKO_CERTIFICATE != objtype)
				rv = CKR_FUNCTION_NOT_SUPPORTED;
		}
		break;

	case CKA_CERTIFICATE_TYPE:
		{
			CK_CERTIFICATE_TYPE cert_type;
			rv = read_attribute(attr, &cert_type, sizeof(cert_type), &val_len);
			if (CKR_OK == rv && CKC_X_509 != cert_type)
				rv = CKR_FUNCTION_NOT_SUPPORTED;
		}
		break;

	case CKA_VALUE:
		{
			unsigned char* buf = attr->pValue;
			*cert = d2i_X509(NULL, (void*)&buf, attr->ulValueLen);
			if (*cert) {
				DEBUG(1, "created new certificate");
			} else {
				ERROR("cannot create certificate");
			}
		}
		break;

	case CKA_TRUSTED:
	case CKA_TOKEN:
	case CKA_PRIVATE:
		{
			CK_BBOOL avalue;
			rv = read_attribute(attr, &avalue, sizeof(avalue), &val_len);
			if (CKR_OK == rv) {
				char* name = "";
				switch (attr->type) {
				case CKA_TRUSTED:
					name = "trusted";
					break;
				case CKA_TOKEN:
					name = "token";
					break;
				case CKA_PRIVATE:
					name = "private";
					break;
				}
				DEBUG(1, "Set cert %s to %s", name, avalue?"true":"false");
			}
		}
		break;
	case CKA_SUBJECT:
	case CKA_ISSUER:
		{
			/*
			 * TODO: enter into certificate
			 */
#if 0
			char name[255];
			memset(name, '\0', sizeof(name));
			rv = read_attribute(attr, name, sizeof(name) - 1, &val_len);
			if (CKR_OK == rv) {
#endif
				DEBUG(1, "Set cert %s", 
					  attr->type == CKA_SUBJECT ? "subject" : "issuer");
#if 0
			}
#endif
		}
		break;

	case CKA_SERIAL_NUMBER:
		{
			ASN1_INTEGER* ival;
			unsigned char* buf = attr->pValue;

			ival = d2i_ASN1_INTEGER(NULL, (void*)&buf, attr->ulValueLen);
			if (NULL != ival) {
				/*
				 * TODO: Set in certificate
				 */
				DEBUG(1,"Set serial number");
				M_ASN1_INTEGER_free(ival);
			}
		}
		break;
				
	case CKA_LABEL:
		{
			char name[255];
			memset(name, '\0', sizeof(name));
			rv = read_attribute(attr, name, sizeof(name) - 1, &val_len);
			if (CKR_OK == rv) {
				DEBUG(1, "Set cert label to %s", name);
			}
		}
		break;

	case CKA_ID:
		{
			unsigned char cert_id[100];
			rv = read_attribute(attr, &cert_id, sizeof(cert_id), &val_len);
			if (CKR_OK == rv)
				DEBUG(1, "Set cert id");
		}
		break;

	default:
		DEBUG(1, "unsupported attribute id %x", (int)attr->type);
		break;
	}
	return(rv);
}

/*
 * Public functions
 */

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	CK_RV rv = CKR_OK;

#ifdef USE_SYSLOG
	openlog("", LOG_PID, LOG_UUCP);
#endif
	DEBUG(1, "enter");
	rv = read_config(&nrof_slots, slot_lst, sizeof(slot_lst)/sizeof(CK_SLOT_ID));
	if (rv == CKR_OK) {
		if (0 != ngsw_certman_open(&root_certs))
			rv = CKR_DEVICE_ERROR;
	}
	DEBUG(1, "exit");
	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	DEBUG(1, "enter");
	release_config();
	ngsw_certman_close(root_certs);
	DEBUG(1, "exit");
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;
	DEBUG(1, "enter");
	memcpy(pInfo, &library_info, sizeof(*pInfo));
	DEBUG(1, "exit");
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(
	CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	DEBUG(1, "enter");
	if (!ppFunctionList)
		return(CKR_ARGUMENTS_BAD);

	*ppFunctionList = (CK_FUNCTION_LIST_PTR)&function_list;
	DEBUG(1, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;

	DEBUG(1, "enter");

	/*
	 * The token is always present, so we can ignore the tokenPresent
	 * argument, both cases always return all slots.
	 * TODO: A lot
	 */
	if (!pulCount) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	if (!pSlotList) {
		*pulCount = nrof_slots;
		DEBUG(1, "exit, just asked the nbrof slots");
		return CKR_OK;
	}

	if (*pulCount < nrof_slots) {
		*pulCount = nrof_slots;
		DEBUG(1, "exit, buffer too small");
		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = nrof_slots;

	for (i = 0; i < nrof_slots; i++)
		pSlotList[i] = slot_lst[i];

	DEBUG(1, "exit");
	return CKR_OK;

  out:
	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	DEBUG(1, "enter");
	if (!pInfo) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	rv = get_slot_info(slotID, pInfo);
	DEBUG(1, "exit");
out:
	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	DEBUG(1, "enter");
	if (!pInfo) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	rv = get_token_info(slotID, pInfo);
	DEBUG(1, "exit");
out:
	return rv;
}
	
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;

	DEBUG(1, "enter");
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
	DEBUG(1, "enter");
	DEBUG(1, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	DEBUG(1, "enter");
	DEBUG(1, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
	CK_VOID_PTR pApplication, CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_OK;

	DEBUG(1, "enter app=%p, notify=%p", pApplication, Notify);
	if (!phSession) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	DEBUG(1, "Opened session for slot %d", (int)slotID);
	*phSession = open_session(slotID);
	DEBUG(1, "exit");
	return CKR_OK;
 out:
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	DEBUG(1, "enter");
	rv = close_session(hSession);
	DEBUG(1, "exit %ld", rv);
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_OK;
	DEBUG(1, "enter");
	rv = close_all_sessions(slotID);
	DEBUG(1, "exit %ld", rv);
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;
	SESSION sess;

	DEBUG(1, "enter");
	GET_SESSION(hSession, sess);

	if (pInfo) {
		pInfo->slotID = sess->slot;
		/*
		 * TODO: Read only or read-write?
		 */
		pInfo->state = CKS_RO_PUBLIC_SESSION;
		pInfo->flags = CKF_SERIAL_SESSION;
	} else {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
 out:
	DEBUG(1, "exit %ld", rv);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv = CKR_OK;
	X509* cert = NULL;
	CK_ULONG i;
	int cert_nbr;
	SESSION sess;

	DEBUG(1, "enter");
	*phObject = -1;
	GET_SESSION(hSession, sess);

	DEBUG(1, "enter");
	for (i = 0; i < ulCount; i++) {
		DEBUG(1, "set %s", attr_name(pTemplate[i].type));
		rv = set_attribute(sess, &cert, &pTemplate[i]);
		if (CKR_OK != rv)
			break;
	}
	if (CKR_OK == rv && NULL != cert) {
		rv = add_cert(sess, cert, &cert_nbr);
		if (CKR_OK == rv)
			*phObject = (CK_OBJECT_HANDLE)cert_nbr;
	}
	DEBUG(1, "exit %lx", rv);
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	DEBUG(1, "enter");
	DEBUG(1, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject)
{
	DEBUG(1, "enter");
	DEBUG(1, "exit");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject, CK_ULONG_PTR pulSize)
{
	DEBUG(1, "enter");
	DEBUG(1, "exit");
	return(CKR_FUNCTION_NOT_SUPPORTED);
}


CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;
	SESSION sess;
	X509* cert;
	CK_ATTRIBUTE_PTR attr;

	DEBUG(1, "get %ld attributes of object %d", ulCount, (int)hObject);
	GET_SESSION(hSession, sess);
	cert = get_cert(sess, hObject);
	if (cert) {
		for (i = 0; i < ulCount; i++) {
			attr = &pTemplate[i];
			DEBUG(1, "get %s", attr_name(attr->type));
			rv = access_attribute(sess, cert, (int)hObject, attr, copy_attribute);
			if (rv != CKR_OK) {
				break;
			}
		}
	} else
		rv = CKR_ARGUMENTS_BAD;
	DEBUG(1, "exit %lx", rv);
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount)
{
	DEBUG(1, "enter");
	DEBUG(1, "exit");
	return(CKR_FUNCTION_NOT_SUPPORTED);
}


CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	SESSION sess;
	CK_ULONG i, val;
	DEBUG(1, "enter %d %p %d", (int)hSession, pTemplate, (int)ulCount);
	GET_SESSION(hSession, sess);
	for (i = 0; i < ulCount; i++) {
		val = *(CK_ULONG*)pTemplate[i].pValue;
#ifdef INCL_NETSCAPE_VDE
		DEBUG(2, "search for %s == %ld:%lx(%lx)", 
			  attr_name(pTemplate[i].type),
			  pTemplate[i].ulValueLen,
			  val,
			  val >= CKO_NSS ? val - CKO_NSS : -1);
#else
		DEBUG(2, "search for %s == %ld:%lx", 
			  attr_name(pTemplate[i].type),
			  pTemplate[i].ulValueLen,
			  val);
#endif
	}
	sess->find_template = pTemplate;
	sess->find_count = ulCount;
	sess->find_point = 0;
	sess->state = sstat_search;
	DEBUG(1, "exit");
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv = CKR_OK;
	SESSION sess;
	CK_ULONG i, j;
	int found = 0, nbrof_certs = 0;

	DEBUG(1, "enter, find at most %d objects", (int)ulMaxObjectCount);
	GET_SESSION(hSession, sess);
	if (sess->state != sstat_search) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		goto out;
	}

	/*
	 * Rationale: iterate through all data objects and compare
	 * their attributes with the given template. If all attributes
	 * match, populate the handle-table. If no attributes are
	 * given in the search template, all objects are returned.
	 */
	nbrof_certs = ngsw_certman_nbrof_certs(sess->cmdomain);
	for (i = sess->find_point; i < nbrof_certs; i++) {
		int is_match = 1;
		X509* cert = get_cert(sess, i);
		for (j = 0; j < sess->find_count; j++) {
			CK_RV tst = access_attribute(sess, cert, i, 
										 &sess->find_template[j],
										 match_attribute);
			if (tst != CKR_OK) {
				is_match = 0;
				if (tst != CKR_CANCEL) {
					ERROR("match_attribute:%lx", tst);
					rv = tst;
					goto out;
				}
				break;
			}
		}
		if (is_match) {
			DEBUG(2, "cert %ld matches", i);
			if (found < ulMaxObjectCount) {
				phObject[found++] = i;
				sess->find_point++;
			} else
				break;
		}
	}
	*pulObjectCount = found;
	DEBUG(1, "found %d of %d", found, nbrof_certs);

  out:
	DEBUG(1, "exit %lx", rv);
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	SESSION sess;
	DEBUG(1, "enter");
	GET_SESSION(hSession, sess);
	sess->find_template = NULL;
	sess->state = sstat_base;
	DEBUG(1, "exit");
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

#define RETATTR(s,x) case s: return(x)

static const char*
attr_name(CK_ATTRIBUTE_TYPE of_a)
{
	switch (of_a) {
		RETATTR(CKA_CLASS,"CKA_CLASS");
		RETATTR(CKA_CERTIFICATE_TYPE,"CKA_CERTIFICATE_TYPE");
	    RETATTR(CKA_VALUE,"CKA_VALUE");
	    RETATTR(CKA_TRUSTED,"CKA_TRUSTED");
		RETATTR(CKA_TOKEN,"CKA_TOKEN");
		RETATTR(CKA_PRIVATE,"CKA_PRIVATE");
		RETATTR(CKA_MODIFIABLE,"CKA_MODIFIABLE");
		RETATTR(CKA_CERTIFICATE_CATEGORY,"CKA_CERTIFICATE_CATEGORY");
		RETATTR(CKA_CHECK_VALUE,"CKA_CHECK_VALUE");
		RETATTR(CKA_START_DATE,"CKA_START_DATE");
		RETATTR(CKA_END_DATE,"CKA_END_DATE");
		RETATTR(CKA_SUBJECT,"CKA_SUBJECT");
		RETATTR(CKA_ISSUER,"CKA_ISSUER");
		RETATTR(CKA_SERIAL_NUMBER,"CKA_SERIAL_NUMBER");
		RETATTR(CKA_LABEL,"CKA_LABEL");
		RETATTR(CKA_ID,"CKA_ID");
	default:
		{
			static char dbg_buf[128];
			sprintf(dbg_buf, "UNKNOWN(%lx)", of_a);
			return(dbg_buf);
		}
	}
}
