/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#ifndef BB5_H
#define BB5_H

#include <openssl/x509v3.h>
#include <openssl/evp.h>

#ifdef	__cplusplus
extern "C" {
#endif

// A stub implementation of the BB5 module for testing in a laptop
extern X509_STORE* bb5_init();
extern void        bb5_finish();

extern ssize_t     bb5_get_random(unsigned char *buf, size_t len);
extern X509*       bb5_get_cert(void);
extern int         bb5_rsakp_sign(EVP_MD_CTX* ctx, unsigned char* md, size_t maxlen);

#ifdef	__cplusplus
}
#endif
#endif
