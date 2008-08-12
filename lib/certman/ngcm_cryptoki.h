/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_cryptoki.h
 * \brief The PKCS#11 interface to the certificate manager
 */


#ifndef NGCM_CRYPTOKI_H
#define NGCM_CRYPTOKI_H

// #pragma pack(push, cryptoki, 1)

/* Specifies that the function is a DLL entry point. */
// #define CK_IMPORT_SPEC __declspec(dllimport)
#define CK_IMPORT_SPEC

/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
 * not define it in applications.
 */
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
// #define CK_EXPORT_SPEC __declspec(dllexport) 
#define CK_EXPORT_SPEC
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif

/* Ensures the calling convention for Win32 builds */
// #define CK_CALL_SPEC __cdecl
#define CK_CALL_SPEC

#define CK_PTR *
#define CK_NULL_PTR (void*)0

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

// #pragma pack(pop, cryptoki)

#endif

