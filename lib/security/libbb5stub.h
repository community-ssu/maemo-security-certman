/* -*- mode:c; tab-width:4; c-basic-offset:4;
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

#ifndef BB5_H
#define BB5_H

#include <openssl/x509v3.h>
#include <openssl/evp.h>

#ifdef	__cplusplus
extern "C" {
#endif

// A stub implementation of the BB5 module for testing in a laptop
void        bb5_init();
void        bb5_finish();

ssize_t     bb5_get_random(unsigned char *buf, size_t len);
X509*       bb5_get_cert(int nbrof);
int         bb5_rsakp_sign(EVP_MD_CTX* ctx, unsigned char* md, size_t maxlen);
ssize_t     bb5_rsakp_decrypt(int set, int key, const unsigned char *msg,
							  size_t len, unsigned char **plain);

#ifdef	__cplusplus
}
#endif
#endif
