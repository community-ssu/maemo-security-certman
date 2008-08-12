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
