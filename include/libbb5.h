#ifndef LIBBB5_H
#define LIBBB5_H


#include <stdlib.h>

/*
 * Symbolic names for certicate id's.
 */
typedef enum {
	BB5_CERT_CCC = 0,
	BB5_CERT_NPC = 1,
	BB5_CERT_HWC = 2,
	BB5_CERT_X509 = 3
} bb5_cert_t;	

/* SuperDongle authentication algorithm names. */
typedef enum {
	BB5_AUTH_AES = 0,
	BB5_AUTH_3DES = 1
} bb5_auth_algo_t;

struct bb5_rsa_key_info {
	int size;
	int services;
	int pub_exp;
	int type;
	unsigned char modulus[1]; /* Will contain size/8 bytes */
};

/*
 * SuperDongle info
 */
struct bb5_sd_info {
	unsigned char type[2];
	unsigned char serial[6];
	unsigned char expdate[3];
};

/*
 * Check presence of the underlying device.
 * Returns zero if device is available, else negative error code.
 */
int bb5_check_device(void);

/*
 * Fill given buffer with random data.
 * Returns number of bytes output or a negative error code.
 */
ssize_t bb5_get_random(unsigned char *buf, size_t len);

/*
 * Rot13 given buffer.
 * Returns number of bytes rot'ed or a negative error code.
 */
ssize_t bb5_rot13(unsigned char *buf, size_t len);

/*
 * Functions for getting response to labeling cmd. The functions work
 * identically, except for the protocol difference indicated in the function
 * name. The functions allocate response buffer and return it in
 * *resp. They return length of response data or a negative error code.
 */
ssize_t bb5_label_resp_npc(unsigned long mask, const unsigned char *buf,
					size_t len, unsigned char **resp);
		
ssize_t bb5_label_resp_rdc(unsigned long mask, const unsigned char *buf,
					size_t len, unsigned char **resp);

ssize_t bb5_label_resp_assk(unsigned long mask, const unsigned char *buf,
					size_t len, unsigned char **resp);

/*
 * Generate an RSA key. The public key is returned in the buffer
 * pointed to by pubkey. Return is zero for success or a negative error code.
 */
ssize_t bb5_rsakp_generate(int type, int set, int key, unsigned long exp,
							unsigned char **pubkey);

/*
 * Delete an RSA key.
 * Return is zero for success or a negative error code.
 */
int bb5_rsakp_delete(int set, int key);

/*
 * Import an RSA key.
 * Returns zero for success or a negative error code.
 */
int bb5_rsakp_import(const unsigned char *buf, size_t len);

/*
 * Sign msg using an RSA key. Allocates output buffer and returns it in
 * *signature. Returns length of output or a negative error code.
 */
ssize_t bb5_rsakp_sign(int set, int key, const unsigned char *msg,
		       size_t len, unsigned char **signature);

/*
 * Decrypt msg using an RSA key. Allocates output buffer and returns it in
 * *plain. Returns length of output or a negative error code.
 */
ssize_t bb5_rsakp_decrypt(int set, int key, const unsigned char *msg,
			  size_t len, unsigned char **plain);

/*
 * Get information on an RSA private key. The function will allocate a
 * struct bb5_rsa_key_info and return its address in *info. Returns zero
 * for success or a negative error code.
 */
int bb5_rsakp_info(int set, int key, struct bb5_rsa_key_info **info);

/*
 * Store a certificate. Will overwrite any existing certificate with the
 * same id. Returns len for success, or a negative error code.
 */
ssize_t bb5_cert_store(bb5_cert_t id, const unsigned char *buf,
			      size_t len);

/*
 * Read a certificate previously stored with given id. Allocates buffer
 * and returns its address in *buf. Returns length of data in *buf or a
 * negative error code.
 */
ssize_t bb5_cert_read(bb5_cert_t id, unsigned char **buf);

/*
 * Delete a certificate. Returns zero if it was successfully deleted, or there
 * wasn't a certificate stored with given id. Returns negative error code
 * if deletion failed.
 */
int bb5_cert_delete(bb5_cert_t id);

/*
 * Import NVM unlocking key to Baxter Peak. 
 * blob: import data
 * blen: length of data in blob
 * hout: if non-NULL then *hout will be set to point to the hash
 *       of the imported key.
 * Returns length of data at *hout, or negative for error.
 */
int bb5_bxp_import(const unsigned char *blob, size_t blen,
			  unsigned char **hout);

/*
 * Export NVM unlocking key from Baxter Peak. Note: requires SuperDongle
 * to have been authenticated. If key is non-NULL, *key will be set to point
 * to a 16-byte buffer containing the exported key.
 * Returns length of data at *key, or negative for error.
 */
int bb5_bxp_export(unsigned char **key);

/*
 * Store SuperDongle keys in secure storage.
 * blob: all data and signatures
 * len:  length of data in blob
 * Returns zero for success, or negative for error.
 */
int bb5_sd_prod_init(const unsigned char *blob, size_t len);

/*
 * SuperDongle authentication phase #1. Session id, chip id and algorithm are
 * returned and stored behind respective pointers, if they are non-NULL.
 * NOTE: You must provide enough space for session and chip id's!
 * session:  session id, 16 bytes
 * chip:     chip-specific public id, 20 bytes
 * algo:     algorithm to use.
 * Returns zero for success, or negative for error.
 */
int bb5_sd_auth_init(unsigned char *session, unsigned char *chip,
			    bb5_auth_algo_t *algo);

/*
 * SuperDongle authentication phase #2. Pass in message id, SD info, session id,
 * and authentication code, and you get SD info out as well as a response
 * message. Returns length of data in *resp, or negative error code.
 */
int bb5_sd_auth(int msgid, struct bb5_sd_info *sdin, int session2,
		       const unsigned char *mac, unsigned char **resp);

/*
 * SuperDongle authentication phase #3: verify.
 * msg: verify message, 16 bytes.
 * mac: message authentication code, 8 bytes.
 * Returns zero for success, or negative for error.
 */
int bb5_sd_verify(const unsigned char *msg, const unsigned char *mac);

#endif /* LIBBB5_H */
