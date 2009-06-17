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
 * \file cryptoki_module.c
 * \brief The PKCS#11 implementation on the certificate manager
 */

#include "cryptoki_module.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <string.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>
#include "cryptoki_config.h"

/*
 * Include Netscape's (Mozilla's) vendor defined extensions
 */
#define INCL_NETSCAPE_VDE 1

#if INCL_NETSCAPE_VDE
#define PR_CALLBACK
#include <../nss/pkcs11n.h>
#endif

/*
 * TODO: Fix this
 */
int has_private_key(X509* cert);
int has_private_key_by_id(maemosec_key_id key_id);

static X509_STORE* root_certs;

static const char* attr_name(CK_ATTRIBUTE_TYPE of_a);
static const char* attr_value(CK_ATTRIBUTE_TYPE of_a, const void* val, const unsigned val_len);

/*
 * Support version 2.20 of the specs
 */
#define CRYPTOKI_VERSION_MAJOR 2
#define CRYPTOKI_VERSION_MINOR 20

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
	#include <../nss/pkcs11f.h>
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
			MAEMOSEC_ERROR("session %d not found", (int)id);	\
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
			if (CKA_VALUE != p->type) {
				MAEMOSEC_DEBUG(2, "%s=%s", 
							   attr_name(p->type),
							   attr_value(p->type, value, size));
			}
			memcpy(p->pValue, value, size);
		} else {
			MAEMOSEC_DEBUG(1, "buf %ld cannot take %ld", p->ulValueLen, size);
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

	if (NULL == p || NULL == p->pValue || NULL == value)
		return(CKR_CANCEL);

	if (p->ulValueLen == size
		&& 0 == memcmp(p->pValue, value, size))
    {
		rv = CKR_OK;
	} else {
		rv = CKR_CANCEL;

#if INCL_NETSCAPE_VDE
		/*
		 * Check if this is a trust flag query, and always return
		 * yes when so. Probably doesn't make sense always, has to
		 * TODO: check later.
		 */
		if (CKA_CLASS == p->type) {
			CK_OBJECT_CLASS objtype = *(CK_OBJECT_CLASS*)p->pValue;
			if (CKO_NSS_TRUST == objtype) {
				rv = CKR_OK;
			}
		}
#endif

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
				 CK_OBJECT_CLASS objtype,
				 X509* cert,
				 int cert_number,
				 CK_ATTRIBUTE_PTR attr,
				 CK_RV callback(const void* value, CK_ULONG size, CK_ATTRIBUTE_PTR p))
{
	CK_RV rv = CKR_OK;

	switch (attr->type) 
		{
		case CKA_CLASS:
			{
				CK_OBJECT_CLASS tmp = objtype;
				rv = callback(&tmp, sizeof(tmp), attr);
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

				if (CKO_PRIVATE_KEY == objtype) {
					MAEMOSEC_DEBUG(1, "*** Trying to read value of private key"); 
					rv = CKR_FUNCTION_FAILED;
					goto out;
				}

				if (CKO_PUBLIC_KEY == objtype) {
					MAEMOSEC_DEBUG(1, "*** Trying to read value of public key");
					rv = CKR_FUNCTION_FAILED;
					goto out;
				}

				len = i2d_X509(cert, &obuf);
				if (len <= 0) {
					MAEMOSEC_ERROR("Cannot encode cert (%d)", len);
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

		case CKA_PRIVATE:
			{
				CK_BBOOL avalue = CK_FALSE;
				if (CKO_PRIVATE_KEY == objtype)
					avalue = CK_TRUE;
				rv = callback(&avalue, sizeof(avalue), attr);
			}
			break;

		case CKA_CERTIFICATE_CATEGORY:
			/*
			 *  PKCS11 v2.0 10.6.2
			 */
#define CK_USER_CERT 1
#define CK_AUTHORITY_CERT 2
#define CK_OTHER_CERT 3
			{
				CK_ULONG avalue = CK_OTHER_CERT;
				if (X509_check_ca(cert))
					avalue = CK_AUTHORITY_CERT;
				else if (has_private_key(cert))
					avalue = CK_USER_CERT;
				rv = callback(&avalue, sizeof(avalue), attr);
			}
			break;

		case CKA_CHECK_VALUE:
#if INCL_NETSCAPE_VDE
		case CKA_CERT_SHA1_HASH:
#endif
			{
				unsigned char sha1_hash [SHA_DIGEST_LENGTH];
				if (X509_digest(cert, EVP_sha1(), sha1_hash, NULL))
					rv = callback(sha1_hash,
								  SHA_DIGEST_LENGTH, 
								  attr);
				else
					rv = CKR_FUNCTION_FAILED;
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

		case CKA_KEY_TYPE:
			{
				/*
				 * TODO: Key type is not always RSA, of course
				 */
				CK_KEY_TYPE key_type = CKK_RSA;
				rv = callback(&key_type, sizeof(key_type), attr);
			}
			break;

		case CKA_MODULUS:
			if (CKO_PRIVATE_KEY == objtype) {
				int rc;
				EVP_PKEY* ppkey = NULL;
				struct rsa_st *rsak = NULL;
				maemosec_key_id key_id;
				ASN1_INTEGER* ival = NULL;
				unsigned char* buf = NULL;
				int len;

				if (0 == strlen(sess->password)) {
					rv = CKR_USER_NOT_LOGGED_IN;
					goto out;
				}
				rc = maemosec_certman_get_key_id(cert, key_id);
				if (0 != rc) {
					MAEMOSEC_ERROR("Cannot get key id (%d)", rc);
					rv = CKR_FUNCTION_FAILED;
					goto out;
				}
				MAEMOSEC_DEBUG(1, "%s: got key id", __func__);
				rc = maemosec_certman_retrieve_key(key_id, &ppkey, sess->password);
				if (0 != rc) {
					MAEMOSEC_ERROR("Cannot open private key (%d)", rc);
					rv = CKR_USER_NOT_LOGGED_IN;
					// rv = CKR_FUNCTION_FAILED;
					goto out;
				}
				MAEMOSEC_DEBUG(1, "%s: got private key", __func__);
				/*
				 * Assume RSA keytype for a while
				 */
				rsak = EVP_PKEY_get1_RSA(ppkey);
				if (NULL == rsak) {
					MAEMOSEC_ERROR("Cannot extract RSA");
					rv = CKR_FUNCTION_FAILED;
					goto out;
				}
				MAEMOSEC_DEBUG(1, "%s: got RSA", __func__);
				ival = BN_to_ASN1_INTEGER(rsak->n, NULL);
				if (NULL == rsak) {
					MAEMOSEC_ERROR("Cannot convert to ASN1_INTEGER");
					rv = CKR_FUNCTION_FAILED;
					goto out;
				}
				len = i2d_ASN1_INTEGER(ival, &buf);
				if (len > 0) {
					rv = callback(buf, len, attr);
				} else {
					MAEMOSEC_ERROR("Cannot encode");
					rv = CKR_FUNCTION_FAILED;
				}
				if (buf)
					OPENSSL_free(buf);
				if (ival)
					ASN1_INTEGER_free(ival);
				if (ppkey)
					EVP_PKEY_free(ppkey);
			} else {
				MAEMOSEC_ERROR("%s: cannot ask modulus from anything but a private key", __func__);
			}
			break;
#if 0
		case CKA_MODULUS_BITS:
			break;
		case CKA_PUBLIC_EXPONENT:
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
				/*
				 * TODO: Think of a better 'nickname'
				 */
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
				int rc;
				maemosec_key_id key_id;
				rc = maemosec_certman_get_key_id(cert, key_id);
				if (0 == rc)
					rv = callback(key_id, sizeof(key_id), attr);
				else
					rc = CKR_FUNCTION_FAILED;
			}
			break;

#if INCL_NETSCAPE_VDE

		case CKA_TRUST_SERVER_AUTH:
		case CKA_TRUST_CODE_SIGNING:
			{
				CK_TRUST trust = CKT_NSS_TRUST_UNKNOWN;
				if (X509_check_ca(cert))
					 trust = CKT_NSS_TRUSTED_DELEGATOR;
				rv = callback(&trust, sizeof(trust), attr);
			}
			break;
		case CKA_TRUST_EMAIL_PROTECTION:
		case CKA_TRUST_CLIENT_AUTH:
			{
				CK_TRUST trust = CKT_NSS_TRUST_UNKNOWN;
				if (!X509_check_ca(cert))
					// trust = CKT_NSS_TRUSTED;
					trust = CKT_NSS_TRUSTED_DELEGATOR;
				rv = callback(&trust, sizeof(trust), attr);
			}
			break;

		case CKA_TRUST_IPSEC_END_SYSTEM:
		case CKA_TRUST_IPSEC_TUNNEL:
		case CKA_TRUST_IPSEC_USER:
		case CKA_TRUST_TIME_STAMPING:
			{
				CK_TRUST trust = CKT_NSS_TRUST_UNKNOWN;
				rv = callback(&trust, sizeof(trust), attr);
			}
			break;

		case CKA_TRUST_STEP_UP_APPROVED:
			{
				CK_BBOOL avalue = CK_TRUE;
				rv = callback(&avalue, sizeof(avalue), attr);
			}
			break;

#endif		

		default:
			MAEMOSEC_DEBUG(1, "unsupported attribute id %x", (int)attr->type);
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
			  CK_OBJECT_CLASS objtype,
			  X509** cert,
			  CK_ATTRIBUTE_PTR attr
) {
	CK_RV rv = CKR_OK;
	CK_ULONG val_len;

	switch (attr->type) {
	case CKA_CLASS:
		{
			CK_OBJECT_CLASS tmp;
			rv = read_attribute(attr, &tmp, sizeof(objtype), &val_len);
			if (CKR_OK == rv && CKO_CERTIFICATE != tmp)
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
			
			if (CKO_PRIVATE_KEY == objtype) {
				MAEMOSEC_DEBUG(1, "*** Trying to set value of private key"); 
				rv = CKR_FUNCTION_FAILED;
				goto out;
			}

			if (CKO_PUBLIC_KEY == objtype) {
				MAEMOSEC_DEBUG(1, "*** Trying to set value of public key");
				rv = CKR_FUNCTION_FAILED;
				goto out;
			}

			*cert = d2i_X509(NULL, (void*)&buf, attr->ulValueLen);
			if (*cert) {
				MAEMOSEC_DEBUG(1, "created new certificate");
			} else {
				MAEMOSEC_ERROR("cannot create certificate");
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
				MAEMOSEC_DEBUG(1, "Set cert %s to %s", name, avalue?"true":"false");
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
				MAEMOSEC_DEBUG(1, "Set cert %s", 
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
				MAEMOSEC_DEBUG(1,"Set serial number");
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
				MAEMOSEC_DEBUG(1, "Set cert label to %s", name);
			}
		}
		break;

	case CKA_ID:
		{
			unsigned char cert_id[100];
			rv = read_attribute(attr, &cert_id, sizeof(cert_id), &val_len);
			if (CKR_OK == rv)
				MAEMOSEC_DEBUG(1, "Set cert id");
		}
		break;

	default:
		MAEMOSEC_DEBUG(1, "unsupported attribute id %x", (int)attr->type);
		break;
	}
  out:
	return(rv);
}

/*
 * Public functions
 */

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	CK_RV rv = CKR_OK;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	rv = read_config(&nrof_slots, slot_lst, sizeof(slot_lst)/sizeof(CK_SLOT_ID));
	if (rv == CKR_OK) {
		if (0 != maemosec_certman_open(&root_certs))
			rv = CKR_DEVICE_ERROR;
	}
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return rv;
}


CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	release_config();
	maemosec_certman_close(root_certs);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	memcpy(pInfo, &library_info, sizeof(*pInfo));
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(
	CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	if (!ppFunctionList)
		return(CKR_ARGUMENTS_BAD);

	*ppFunctionList = (CK_FUNCTION_LIST_PTR)&function_list;
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;
}


CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

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
		MAEMOSEC_DEBUG(1, "exit, just asked the nbrof slots");
		return CKR_OK;
	}

	if (*pulCount < nrof_slots) {
		*pulCount = nrof_slots;
		MAEMOSEC_DEBUG(1, "exit, buffer too small");
		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = nrof_slots;

	for (i = 0; i < nrof_slots; i++)
		pSlotList[i] = slot_lst[i];

	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;

  out:
	return rv;
}


CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	if (!pInfo) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	rv = get_slot_info(slotID, pInfo);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
out:
	return rv;
}


CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	if (!pInfo) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	rv = get_token_info(slotID, pInfo);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
out:
	return rv;
}

	
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
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
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;
}


CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;
}


CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
	CK_VOID_PTR pApplication, CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_OK;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	if (!phSession) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	MAEMOSEC_DEBUG(1, "Opened session for slot %d", (int)slotID);
	*phSession = open_session(slotID);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;
 out:
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	rv = close_session(hSession);
	MAEMOSEC_DEBUG(1, "exit %ld", rv);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_OK;
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	rv = close_all_sessions(slotID);
	MAEMOSEC_DEBUG(1, "exit %ld", rv);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;
	SESSION sess;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	GET_SESSION(hSession, sess);

	if (pInfo) {
		pInfo->slotID = sess->slot;
		/*
		 * TODO: Read only or read-write?
		 */
		if (0 == strlen(sess->password))
			pInfo->state = CKS_RO_PUBLIC_SESSION;
		else
			pInfo->state = CKS_RO_USER_FUNCTIONS;
		pInfo->flags = CKF_SERIAL_SESSION;
	} else {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
 out:
	MAEMOSEC_DEBUG(1, "exit %ld", rv);
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

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	*phObject = -1;
	GET_SESSION(hSession, sess);

	for (i = 0; i < ulCount; i++) {
		MAEMOSEC_DEBUG(1, "set %s", attr_name(pTemplate[i].type));
		rv = set_attribute(sess, CKO_CERTIFICATE, &cert, &pTemplate[i]);
		if (CKR_OK != rv)
			break;
	}
	if (CKR_OK == rv && NULL != cert) {
		rv = add_cert(sess, cert, &cert_nbr);
		if (CKR_OK == rv)
			*phObject = (CK_OBJECT_HANDLE)cert_nbr + 1;
	}
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject)
{
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject, CK_ULONG_PTR pulSize)
{
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return(CKR_FUNCTION_NOT_SUPPORTED);
}


#define PKEY_LIMIT 10000
#define PPKEY_LIMIT 20000


CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;
	SESSION sess;
	X509* cert;
	CK_ATTRIBUTE_PTR attr;
	CK_OBJECT_CLASS objtype = CKO_CERTIFICATE;

	GET_SESSION(hSession, sess);
	MAEMOSEC_DEBUG(1, "get %ld attributes of object %s:%d", ulCount, 
				   sess->domain_name, (int)hObject);

	/*
	 * TODO: If public keys are also accessed this way,
	 * need to reserve an area for them, too
	 */
	if (hObject > PKEY_LIMIT) {
		if (hObject > PPKEY_LIMIT) {
			MAEMOSEC_DEBUG(1, "Object is private key");
			hObject -= PPKEY_LIMIT;
			objtype = CKO_PRIVATE_KEY;
		} else {
			MAEMOSEC_DEBUG(1, "Object is public key");
			hObject -= PKEY_LIMIT;
			objtype = CKO_PUBLIC_KEY;
		}
	}

	cert = get_cert(sess, hObject - 1);
	if (cert) {
		for (i = 0; i < ulCount; i++) {
			attr = &pTemplate[i];
			MAEMOSEC_DEBUG(1, "get %s", attr_name(attr->type));
			rv = access_attribute(sess, objtype, cert, (int)hObject - 1, attr, copy_attribute);
			if (rv != CKR_OK) {
				break;
			}
		}
	} else
		rv = CKR_ARGUMENTS_BAD;

	MAEMOSEC_DEBUG(5, "%s: exit %lx", __func__, rv);
	return(rv);
}


CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount)
{
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return(CKR_FUNCTION_NOT_SUPPORTED);
}


CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	SESSION sess;
	CK_ULONG i;

	GET_SESSION(hSession, sess);
	MAEMOSEC_DEBUG(1, "%s: search from '%s'", __func__, sess->domain_name);

	for (i = 0; i < ulCount; i++) {
		MAEMOSEC_DEBUG(2, "  cond %s=%s", 
					   attr_name(pTemplate[i].type),
					   attr_value(pTemplate[i].type, 
								  pTemplate[i].pValue, 
								  pTemplate[i].ulValueLen));
	}
	sess->find_template = pTemplate;
	sess->find_count = ulCount;
	sess->find_point = 0;
	sess->state = sstat_search;
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE_PTR type_attr_ptr = NULL;
	CK_OBJECT_CLASS objtype = (CK_OBJECT_CLASS)-1;
	SESSION sess;
	CK_ULONG i, j;
	int found = 0, nbrof_certs = 0;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	GET_SESSION(hSession, sess);
	if (sess->state != sstat_search) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		goto out;
	}

	/*
	 * Check what kind of an object we are searching for.
	 * Supported types are certificates and private keys,
	 * certificate being default.
	 */
	objtype = CKO_CERTIFICATE;
	for (i = 0; i < sess->find_count; i++) {
		if (CKA_CLASS == sess->find_template[i].type) {
			objtype = *(CK_OBJECT_CLASS*)sess->find_template[i].pValue;
			type_attr_ptr = &sess->find_template[i];
			break;
		}
	}

	if (CKO_CERTIFICATE == objtype || CKO_NSS_TRUST == objtype || CKO_PUBLIC_KEY == objtype) {
		MAEMOSEC_DEBUG(1, "Searching for a certificate, trust or public key");
		/*
		 * Iterate through all data objects and compare their 
		 * attributes with the given template. If all attributes
		 * match, populate the handle-table. If no attributes are
		 * given in the search template, all objects are considered
		 * a match.
		 */
		nbrof_certs = maemosec_certman_nbrof_certs(sess->cmdomain);
		if (0 > nbrof_certs) {
			MAEMOSEC_ERROR("Nonexistent domain (race?)");
			goto out;
		}

		for (i = sess->find_point; i < nbrof_certs; i++) {
			int is_match = 1;
			X509* cert = get_cert(sess, i);
			for (j = 0; j < sess->find_count; j++) {
				CK_RV tst = access_attribute(sess, objtype, cert, i, 
											 &sess->find_template[j],
											 match_attribute);
				if (tst != CKR_OK) {
					is_match = 0;
					if (tst != CKR_CANCEL) {
						MAEMOSEC_ERROR("match_attribute:%lx", tst);
						rv = tst;
						goto out;
					}
					break;
				}
			}
			if (is_match) {
				MAEMOSEC_DEBUG(2, "cert %ld matches", i);
				if (found < ulMaxObjectCount) {
					if (CKO_PUBLIC_KEY == objtype) {
						phObject[found++] = i + 1 + PKEY_LIMIT;
						MAEMOSEC_DEBUG(2, "object %d is public key", 1 + PKEY_LIMIT);
					} else
						phObject[found++] = i + 1;
				} else {
					/*
					 * No more objects fit in the answer.o
					 * Remember where to Continue the search 
					 * in the next call.
					 */
					sess->find_point = i;
					break;
				}
			}
		}
	} else if (CKO_PRIVATE_KEY == objtype) {
		maemosec_key_id key_id;
		int id_is_defined = 0;
		/*
		 * Do not search but get the key according to the given id.
		 */
		MAEMOSEC_DEBUG(1, "Searching for a private key.");
		for (i = 0; i < sess->find_count; i++) {
			if (CKA_ID == sess->find_template[i].type) {
				if (sess->find_template[i].ulValueLen != MAEMOSEC_KEY_ID_LEN) {
					MAEMOSEC_ERROR("key id len mismatch %d != %d", 
								   sess->find_template[i].ulValueLen, 
								   MAEMOSEC_KEY_ID_LEN);
					goto out;
				} else {
					memcpy(key_id, sess->find_template[i].pValue, MAEMOSEC_KEY_ID_LEN);
					id_is_defined = 1;
				}
				break;
			}
		}
		if (id_is_defined) {
			if (has_private_key_by_id(key_id)) {
				MAEMOSEC_DEBUG(1, "%s: has private key", __func__);
				if (found < ulMaxObjectCount) {
					phObject[found++] = PPKEY_LIMIT + 1;
					MAEMOSEC_DEBUG(2, "object %d is private key", 1 + PPKEY_LIMIT);
				}
			}
		} else {
			MAEMOSEC_ERROR("Free private key search");
		}
	} else {
		if (NULL != type_attr_ptr) {
			MAEMOSEC_DEBUG(1, "Unsupported object type '%s'", 
						   attr_value(type_attr_ptr->type, 
									  type_attr_ptr->pValue,
									  type_attr_ptr->ulValueLen));
		} else {
			MAEMOSEC_ERROR("Object type not defined, cannot search");
		}
	}
		
	*pulObjectCount = found;
	MAEMOSEC_DEBUG(1, "found %d of %d", found, nbrof_certs);

  out:
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	SESSION sess;
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	GET_SESSION(hSession, sess);
	sess->find_template = NULL;
	sess->state = sstat_base;
	MAEMOSEC_DEBUG(1, "Exit %s", __func__);
	return CKR_OK;
}

/*
 * Unsupported functions
 */
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
	SESSION sess;
	GET_SESSION(hSession, sess);
	if (sizeof(sess->password) > ulPinLen) {
		memcpy(sess->password, pPin, ulPinLen);
		sess->password[ulPinLen] = '\0';
	} else {
		memcpy(sess->password, pPin, sizeof(sess->password));
		sess->password[sizeof(sess->password) - 1] = '\0';
	}
	MAEMOSEC_DEBUG(1, "%s: %s password %s", 
				   __func__, sess->domain_name, 
				   sess->password);
	return CKR_OK;
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
	int rc;
	CK_RV rv = CKR_OK;
	SESSION sess;
	maemosec_key_id key_id;
	EVP_PKEY *ppkey;
	X509 *cert;

	if (NULL == pMechanism)
		return(CKR_ARGUMENTS_BAD);

	MAEMOSEC_DEBUG(1, "Enter %s, mechanism=0x%x", __func__, pMechanism->mechanism);

	GET_SESSION(hSession, sess);

	sess->signing_algorithm = pMechanism->mechanism;

	if (hKey <= PPKEY_LIMIT) {
		MAEMOSEC_ERROR("%s: %d is not a private key handle", __func__, hKey);
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	if (0 == strlen(sess->password)) {
		MAEMOSEC_ERROR("%s: no password available", __func__);
		rv = CKR_USER_NOT_LOGGED_IN;
		goto out;
	}

	cert = get_cert(sess, hKey - PPKEY_LIMIT - 1);
	if (!cert) {
		MAEMOSEC_ERROR("%s: cannot get cert", __func__);
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	MAEMOSEC_DEBUG(1, "%s: got cert", __func__);

	rc = maemosec_certman_get_key_id(cert, key_id);
	if (0 != rc) {
		MAEMOSEC_ERROR("%s: cannot get key id (%d)", __func__, rc);
		rv = CKR_FUNCTION_FAILED;
		goto out;
	}
	MAEMOSEC_DEBUG(1, "%s: got key id", __func__);

	rc = maemosec_certman_retrieve_key(key_id, &ppkey, sess->password);
	if (0 != rc) {
		MAEMOSEC_ERROR("Cannot open private key (%d)", rc);
		rv = CKR_USER_NOT_LOGGED_IN;
		// rv = CKR_FUNCTION_FAILED;
		goto out;
	}
	MAEMOSEC_DEBUG(1, "%s: got private key", __func__);

	sess->signing_key = ppkey;
	
 out:
	return(rv);
}

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen)
{
	int rc;
	CK_RV rv = CKR_OK;
	SESSION sess;
	EVP_MD_CTX signctx;
	unsigned signature_len = 0;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

	GET_SESSION(hSession, sess);
	if (NULL == sess->signing_key) {
		return(CKR_ARGUMENTS_BAD);
	}

	switch (sess->signing_algorithm) {
	case CKM_SHA1_RSA_PKCS:
		signature_len = EVP_MD_size(EVP_sha1());
		rc = EVP_SignInit(&signctx, EVP_sha1());
		break;
	default:
		MAEMOSEC_ERROR("%s: %d is not a supported mechanism", 
					   __func__, sess->signing_algorithm);
		return(CKR_FUNCTION_NOT_SUPPORTED);
		goto out;
	}


	if (signature_len > *pulSignatureLen) {
		rv = CKR_DATA_LEN_RANGE;
		goto out;
	}
		
	rc = EVP_SignUpdate(&signctx, pData, ulDataLen);
	rc = EVP_SignFinal(&signctx, pSignature, (unsigned*)pulSignatureLen, sess->signing_key);

 out:
	EVP_MD_CTX_cleanup(&signctx);
	return(rv);
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

/*
 * Some help functions
 */
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
		RETATTR(CKA_KEY_TYPE,"CKA_KEY_TYPE");
		RETATTR(CKA_MODULUS,"CKA_MODULUS");
#if INCL_NETSCAPE_VDE
		RETATTR(CKA_TRUST_SERVER_AUTH,"CKA_TRUST_SERVER_AUTH");
		RETATTR(CKA_TRUST_CLIENT_AUTH,"CKA_TRUST_CLIENT_AUTH");
		RETATTR(CKA_TRUST_EMAIL_PROTECTION,"CKA_TRUST_EMAIL_PROTECTION");
		RETATTR(CKA_TRUST_CODE_SIGNING,"CKA_TRUST_CODE_SIGNING");
		RETATTR(CKA_TRUST_IPSEC_END_SYSTEM,"CKA_TRUST_IPSEC_END_SYSTEM");
		RETATTR(CKA_TRUST_IPSEC_TUNNEL,"CKA_TRUST_IPSEC_TUNNEL");
		RETATTR(CKA_TRUST_IPSEC_USER,"CKA_TRUST_IPSEC_USER");
		RETATTR(CKA_TRUST_TIME_STAMPING,"CKA_TRUST_TIME_STAMPING");
		RETATTR(CKA_TRUST_STEP_UP_APPROVED,"CKA_TRUST_STEP_UP_APPROVED");
		RETATTR(CKA_CERT_SHA1_HASH,"CKA_CERT_SHA1_HASH");
		RETATTR(CKA_CERT_MD5_HASH,"CKA_CERT_MD5_HASH");
#endif
	default:
		{
			char aname [64], *c;
			sprintf(aname, "Unknown attribute %lX(CKA_TRUST+%ld)", 
				(CK_ULONG) of_a, 
				(CK_ULONG) (of_a - CKA_TRUST));
			c = (char*)dynhex((unsigned char*)aname, strlen(aname));
			strcpy(c, aname);
			return(c);
		}
	}
}

static const char*
attr_value(CK_ATTRIBUTE_TYPE of_a, const void* val, const unsigned len)
{
	const char* dhbuf = dynhex((unsigned char*)val, len);
	size_t dhlen = 2*len + 1;

	switch(of_a) 
		{
		case CKA_CLASS:
			switch (*(CK_ULONG*)val)
				{
				case CKO_DATA:
					return("CKO_DATA");
				case CKO_CERTIFICATE:
					return("CKO_CERTIFICATE");
				case CKO_PUBLIC_KEY:
					return("CKO_PUBLIC_KEY");
				case CKO_PRIVATE_KEY:
					return("CKO_PRIVATE_KEY");
				case CKO_SECRET_KEY:
					return("CKO_SECRET_KEY");
				case CKO_HW_FEATURE:
					return("CKO_HW_FEATURE");
				case CKO_DOMAIN_PARAMETERS:
					return("CKO_DOMAIN_PARAMETERS");
				case CKO_MECHANISM:
					return("CKO_MECHANISM");
#if INCL_NETSCAPE_VDE 
				case CKO_NSS_CRL:
					return("CKO_NSS_CRL");
				case CKO_NSS_SMIME:
					return("CKO_NSS_SMIME");
				case CKO_NSS_TRUST:
					return("CKO_NSS_TRUST");
				case CKO_NSS_BUILTIN_ROOT_LIST:
					return("CKO_NSS_BUILTIN_ROOT_LIST");
				case CKO_NSS_NEWSLOT:
					return("CKO_NSS_NEWSLOT");
				case CKO_NSS_DELSLOT:
					return("CKO_NSS_NEWSLOT");
#endif
				}
			/* Fall through */

		case CKA_CERTIFICATE_TYPE:
		case CKA_CERTIFICATE_CATEGORY:
			snprintf((char*)dhbuf, dhlen, "%X", *(int*)val);
			break;

		case CKA_TRUSTED:
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		{
			CK_BBOOL bval = *(CK_BBOOL*)val;
			if (CK_TRUE == bval)
				return("True");
			else
				return("False");
			break;
		}

		case CKA_KEY_TYPE:
			switch(*(int*)val) {
			case CKK_RSA: return("RSA");
			case CKK_DSA: return("DSA");
			case CKK_DH: return("DH");
			case CKK_KEA: return("KEA");
			case CKK_EC: return("EC");
			default: return("(Unknown)");
			}

#if INCL_NETSCAPE_VDE 
		case CKA_TRUST_STEP_UP_APPROVED:
			if (*(int*)val)
				return("True");
			else
				return("False");
			break;

		case CKA_TRUST_SERVER_AUTH:
		case CKA_TRUST_CLIENT_AUTH:
		case CKA_TRUST_EMAIL_PROTECTION:
		case CKA_TRUST_CODE_SIGNING:
			{
				CK_TRUST trust;

				memcpy(&trust, val, len);
				switch (trust)
					{
					case CKT_NSS_TRUSTED:
						return("Trusted");
					case CKT_NSS_TRUSTED_DELEGATOR:
						return("Trusted delegator");
					case CKT_NSS_UNTRUSTED:
						return("Untrusted");
					case CKT_NSS_MUST_VERIFY:
						return("Must verify");
					case CKT_NSS_TRUST_UNKNOWN:
						return("Trust unknown");
					default:
						return("Unknown trust value");
					}
			}
			break;
#endif

		case CKA_SUBJECT:
		case CKA_ISSUER:
			{
				void* buf = (void*)val;
				X509_NAME *xn = d2i_X509_NAME(NULL, (void*)&buf, (long)len);
				if (xn)
					X509_NAME_oneline(xn, (char*)dhbuf, dhlen);
#if 0
				{
					int i;
					MAEMOSEC_DEBUG(2, "%s: %s", __func__, dhbuf);
					for (i = 0; i < sk_X509_NAME_ENTRY_num(xn->entries); i++) {
						X509_NAME_ENTRY *ne = sk_X509_NAME_ENTRY_value(xn->entries, i);
						ASN1_STRING *asn1_string = NULL;
						unsigned char *utf8_string = NULL;
						
						if (NULL != ne)
							asn1_string = ne->value;
						if (NULL != asn1_string) 
							ASN1_STRING_to_UTF8(&utf8_string, asn1_string);
						if (NULL != utf8_string) {
							MAEMOSEC_DEBUG(2, "%s: UTF8 string='%s'", __func__, utf8_string);
							OPENSSL_free(utf8_string);
						}
					}
				}
#endif
			}
			break;

#if 0
		case CKA_SERIAL_NUMBER:
			{
				ASN1_INTEGER* ival;
				char* tbuf = NULL;

				ival = d2i_ASN1_INTEGER(NULL, val, len);
				if (ival) {
					i2c_ASN1_INTEGER(ival, (unsigned char**)&tbuf);
					if (tbuf) {
						strncpy((char*)dhbuf, tbuf, dhlen);
						OPENSSL_free(tbuf);
					}
					ASN1_INTEGER_free(ival);
				}
			}
#endif
		default:
			;
		}
	return(dhbuf);
}
