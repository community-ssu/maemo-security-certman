/*
 * libbb5.c
 *
 * Function call interface to /dev/omap_sec
 *
 * Copyright (c) Nokia 2007.
 * Written by Timo O. Karjalainen <timo.o.karjalainen@nokia.com>
 */


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <cal.h>
#include <asm/types.h>
#include "linux/asm/arch-omap/sec.h"
#include "libbb5.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define SEC_PA_FIRST 0x100

enum pa_cmds {
	SEC_CMD_INIT = 1,
	SEC_CMD_SECS = 2,
	OMAP_SEC_CMD_ROT13 = SEC_PA_FIRST,
	OMAP_SEC_CMD_LABEL_RESP_SIZE,
	OMAP_SEC_CMD_LABEL_RESP_NPC,
	OMAP_SEC_CMD_LABEL_RESP_RDC,
	OMAP_SEC_CMD_LABEL_RESP_ASSK,
	OMAP_SEC_CMD_RSAKP_GENERATE,
	OMAP_SEC_CMD_RSAKP_DELETE,
	OMAP_SEC_CMD_RSAKP_IMPORT,
	OMAP_SEC_CMD_RSAKP_SERVICE,
	OMAP_SEC_CMD_RSAKP_KEY_INFO,
	OMAP_SEC_CMD_BXP_IMPORT = 0x10c,
	OMAP_SEC_CMD_BXP_EXPORT = 0x10d,
	OMAP_SEC_CMD_SD_PROD_INIT = 0x10e,
	OMAP_SEC_CMD_SD_AUTH_INIT = 0x10f,
	OMAP_SEC_CMD_SD_AUTH = 0x110,
	OMAP_SEC_CMD_SD_VERIFY = 0x111,
};

#define OMAP_SEC_RSAKP_TYPE_DECRYPT_PKCS1_v1_5		0x1
#define OMAP_SEC_RSAKP_TYPE_SIGN_PKCS1_v1_5      	0x2
#define OMAP_SEC_RSAKP_TYPE_NO_PADDING_PRIVATE_KEY	0x4

#define OMAP_SEC_RSAKP_PUBKEY_SIZE  276

/*
 * Magic return code from RSA key generation PA:
 * Did not find primes, try again.
 */
#define SEC_RSA_GEN_FAIL	28

/* How many times we retry if PA gives above error */
#define SEC_RSA_GEN_RETRY_ATTEMPTS	10

static const char dev[] = "/dev/omap_sec";

/* todo: declare mutex to protect fd-operations*/
static int fd = -1;

/*
 * Write a byte.
 */
static int write_8(uint8_t b)
{
	if (write(fd, &b, 1) != 1)
		return -1;

	return 0;
}

/*
 * Write 16 bits.
 */
static int write_16(uint16_t i)
{
	if (write(fd, &i, 2) != 2)
		return -1;

	return 0;
}

/*
 * Write a 32-bit number.
 */
static int write_32(uint32_t num)
{
	if (write(fd, &num, 4) != 4)
		return -1;

	return 0;
}

/*
 * Write a device command followed by length.
 */
static int write_cmd(uint32_t cmd, uint32_t size)
{
	int r;

	r = write_32(cmd);
	if (r)
		return r;

	r = write_32(size);
	if (r)
		return r;

	return 0;
}

/*
 * Write data to the device. Wraps write() return semantics
 * to success/errorcode return value.
 */
static int write_data(const void *buf, size_t len)
{
	if (write(fd, buf, len) != len)
		return -1;

	return 0;
}

static int read_data(void *buf, size_t len)
{
	size_t ret;
	
	ret = read(fd, buf, len);
	
	if (ret == len)
		return 0;

	/*
	 * Device may report EAGAIN if it thinks we have already read
	 * all there is to read. However, from libbb5 user's point of view
	 * the libbb5 call _fails_ if libbb5 cannot read expected data from
	 * the device. Therefore libbb5 should not return EAGAIN in errno
	 * when the same call done again will not work any better.
	 */
	if (errno == EAGAIN)
		errno = EIO;

	return -1;
}

static int read_8(uint8_t *b)
{
	return read_data(b, 1);
}

static int read_16(uint16_t *b)
{
	return read_data(b, 2);
}

/*
 * Read 4 bytes from device into an integer.
 * Returns zero for success, or a negative error code.
 */
static int read_32(uint32_t *res)
{
	return read_data(res, 4);
}


struct ret_code {
	uint32_t	ret;		/* Return code from secure side */
	int		unixerr;	/* Unix error code for errno */
};

/* Return codes from secure ROM */
static const struct ret_code rom_ret[] = {
	{ SEC_HAL_OK,		0	},	/* no error */
	{ SEC_HAL_NOTEXEC,	ENOEXEC	},
	{ SEC_HAL_FAIL,		EINVAL	},
	{ SEC_HAL_ENOMEM,	ENOMEM	},
	{ SEC_HAL_ENOPA,	ENXIO	},
};

/* Return codes from Protected Application */
static const struct ret_code pa_ret[] = {
	{ SEC_HAL_OK,		0	},	/* no error */
	{ SEC_HAL_NOTEXEC,	ENOEXEC	},
	{ SEC_RSA_GEN_FAIL,	EAGAIN	},
};

static int check_return(uint32_t ret, const struct ret_code *tbl, size_t num,
			const char *type)
{	
	int i;

	for (i = 0; i < num; i++) {
		if (tbl[i].ret == ret) {
			if (tbl[i].unixerr) {
				errno = tbl[i].unixerr;
				goto error;
			}

			return 0;
		}
	}

error:
	syslog(LOG_ERR, "%s error 0x%08x\n", type, ret);
	return -1;
}

/*
 * Read success code from device. For device commands there is 4 bytes;
 * for PA calls there is another 4 bytes. If device reports an error from ROM
 * or PA, it is mapped to appropriate Unix errno error code and written to
 * errno. -1 is then returned. For success, 0 is returned and errno is not
 * touched.
 */
static int read_result(uint32_t cmd)
{
	int r;
	uint32_t ret;

	if ((r = read_32(&ret)))
		return r;

	r = check_return(ret, rom_ret, ARRAY_SIZE(rom_ret), "rom");
	if (r)
		return r;

	if (cmd >= SEC_PA_FIRST) {
		if ((r = read_32(&ret)))
			return r;

		return check_return(ret, pa_ret, ARRAY_SIZE(pa_ret), "pa");
	}

	return 0;
}

static const char secs_name[] = "secure_storage";

/*
 * Read secure storage from CAL and feed it to the device.
 */
static int secs_to_device(void)
{
	int ret;
	struct cal *cal;
	void *buf = NULL;
	unsigned long len;

	if (cal_init(&cal) < 0)
		return 0;

	if (cal_read_block(cal, secs_name, &buf, &len, CAL_FLAG_USER) < 0)
		len = 0;

	//syslog(LOG_INFO, "secs_to_device: sending %d bytes of secs\n", len);
	ret = write_cmd(SEC_CMD_INIT, len);	
	if ((!ret) && len)
		ret = write_data(buf, len);

	if (buf)
		free(buf);

	if (!ret)
		ret = read_result(SEC_CMD_INIT);

	cal_finish(cal);
	return ret? ret : 0;
}

static int close_device(void)
{
	close(fd);
	fd = -1;
}

/*
 * Initiate a secure storage download from device.
 * Returns a file descriptor for a parallel open of the device;
 * this is the fd on which the secs download takes place.
 * Feed the returned fd to secs_to_cal_finish() after the operation
 * which changes secs content.
 * Return value is negative if any error occurred.
 */
static int secs_to_cal_begin(void)
{
	int secsfd;
	unsigned long buf;

	secsfd = open(dev, O_RDWR);

	if (secsfd == -1)
		return -1;

	buf = SEC_CMD_SECS;
	write(secsfd, &buf, 4);
	buf = 0;
	write(secsfd, &buf, 4);

	/*
	if ((r = write_cmd(SEC_CMD_SECS, 0))) {
		close(secsfd);
		return r;
	}
	*/

	return secsfd;
}

/*
 * Latter part of secure storage download. Pass in the file descriptor
 * returned from secs_to_cal_begin(). This function will read the secs
 * from the device and store it in CAL. Returns zero for success, or
 * negative for error.
 */
static int secs_to_cal_finish(int secsfd)
{
	struct cal *cal;
	void *buf;
	uint32_t len;
	int r = 0;

	/*
	if ((r = write_cmd(SEC_CMD_SECS, 0)))
		return r;
	*/

	read(secsfd, &len, 4);
	/*if ((r = read_32(&len)))
		return r;*/

	buf = malloc(len);
	if (!buf) {
		/* TODO: should first read 'len' bytes from the device
		   piece-by-piece into a small stack buffer...*/
		return ENOMEM;
	}

	read(secsfd, buf, len);
	/*if (r = read_data(buf, len))
		return r;*/

	close(secsfd);

	if (cal_init(&cal) < 0) {
		free(buf);
		return -1;
	}

	if (cal_write_block(cal, secs_name, buf, len, CAL_FLAG_USER) < 0) {
		r = -1;
	}

	cal_finish(cal);

	free(buf);

	return r;
}

/*
 * Open the device. If open succeeds, secure storage data is fed to the
 * device as CMD_INIT data. Returns -1 for error (errno has error code),
 * or 0 for success.
 */
static int open_device(void)
{
	if (fd != -1)
		return 0;

	fd = open(dev, O_RDWR | O_NONBLOCK);
	if (fd == -1)
		return -1;

	openlog("bb5", LOG_PERROR, LOG_USER);
	
	return secs_to_device();
}

/*
 * Check presence of the underlying device.
 * Returns zero if device is available, else negative error code.
 */
int bb5_check_device(void)
{
	return access(dev, R_OK | W_OK);
}

/*
 * Fill given buffer with random data.
 * Returns number of bytes output, or -1 for error; error code is in errno.
 */
ssize_t bb5_get_random(unsigned char *buf, size_t len)
{
	int r, pa_ret;

	/* todo: obtain fd-mutex and release it in all cases */

	if ((r = open_device()))
		return r;

	if ((r = write_cmd(CMD_RANDOM, 4)))
		return r;

	if ((r = write_32(len)))
		return r;

	if ((r = read_result(CMD_RANDOM)))
		return r;

	return read(fd, buf, len);
}

/*
 * Rot13 given buffer.
 * Returns number of bytes rot'ed or -1 for error. Check errno for error code
 * in case of error.
 */
ssize_t bb5_rot13(unsigned char *buf, size_t len)
{
	int r;

	/* todo: obtain fd-mutex and release it in all cases */

	if ((r = open_device()))
		return r;

	if ((r = write_cmd(OMAP_SEC_CMD_ROT13, 4 + len)))
		return r;

	if ((r = write_32(len)))
		return r;

	if ((r = write_data(buf, len)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_ROT13)))
		return r;

	return read(fd, buf, len);
}

/*
 * Given a labeling message mask, ask the device how much output space
 * it will need to respond. Returns negative for error, or the length.
 */

static ssize_t label_resp_size(unsigned long mask)
{
	int r;
	uint32_t size;

	if ((r = write_cmd(OMAP_SEC_CMD_LABEL_RESP_SIZE, 4)))
		return r;

	if ((r = write_32(mask)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_LABEL_RESP_SIZE)))
		return r;

	if ((r = read_32(&size)))
		return r;

	return size;
}
		
/*
 * Get response to labeling cmd. Allocates response buffer and returns it in
 * *resp. Returns length of response data or a negative error code.
 */
static ssize_t label_resp(unsigned long cmd, unsigned long mask,
		const unsigned char *buf, size_t len, unsigned char **resp)
{
	int r;
	ssize_t out_len;

	if (!*resp) {
		errno = EINVAL;
		return -1;
	}

	/* todo: obtain fd-mutex and release it in all cases */

	if ((r = open_device()))
		return r;

	out_len = label_resp_size(mask);
	if (out_len < 0)
		return -1;

	if ((r = write_cmd(cmd, len + 4 + 4)))
		return r;

	if ((r = write_data(buf, len)))
		return r;

	if ((r = write_32(mask)))
		return r;

	if ((r = write_32(out_len)))
		return r;

	if ((r = read_result(cmd)))
		return r;

	if (!(*resp = malloc(out_len))) {
		errno = ENOMEM;
		return -1;
	}

	if ((r = read_data(*resp, out_len))) {
		free(*resp);
		*resp = NULL;
		return r;
	}

	return out_len;
}

/* Dedicated functions for various kinds of label messages. */

ssize_t bb5_label_resp_npc(unsigned long mask, const unsigned char *buf,
					size_t len, unsigned char **resp)
{
	return label_resp(OMAP_SEC_CMD_LABEL_RESP_NPC, mask, buf, len, resp);
}
		
ssize_t bb5_label_resp_rdc(unsigned long mask, const unsigned char *buf,
					size_t len, unsigned char **resp)
{
	return label_resp(OMAP_SEC_CMD_LABEL_RESP_RDC, mask, buf, len, resp);
}

ssize_t bb5_label_resp_assk(unsigned long mask, const unsigned char *buf,
					size_t len, unsigned char **resp)
{
	return label_resp(OMAP_SEC_CMD_LABEL_RESP_ASSK, mask, buf, len, resp);
}

/*
 * Generate an RSA key. The public key is returned in the buffer
 * pointed to by pubkey. Return is length of pubkey or -1 for error;
 * errno has details.
 */
ssize_t bb5_rsakp_generate(int type, int set, int key, unsigned long exp,
						unsigned char **pubkey)
{
	int r, retries, secsfd;
	size_t len = OMAP_SEC_RSAKP_PUBKEY_SIZE;
	unsigned char status;

	if (!pubkey) {
		errno = EINVAL;
		return -1;
	}

	if ((r = open_device()))
		return r;

	secsfd = secs_to_cal_begin();
	if (secsfd < 0)
		return -1;

	/*
	 * If the RSA key generating PA does not find primes, it gives up.
	 * We retry a few times before returning EAGAIN to caller.
	 */
	for (retries = 0; retries < SEC_RSA_GEN_RETRY_ATTEMPTS; retries++) {
		r = write_cmd(OMAP_SEC_CMD_RSAKP_GENERATE, 1 + 1 + 2 + 4);
		if (r)
			return r;

		if ((r = write_8(set)))
			return r;

		if ((r = write_8(key)))
			return r;

		if ((r = write_16(type)))
			return r;

		if ((r = write_32(exp)))
			return r;

		r = read_result(OMAP_SEC_CMD_RSAKP_GENERATE);
		if (r) {
			if (errno == EAGAIN)
				continue;
			else
				return r;
		}
		else
			break;
	}

	/* todo: what should we do with status? */
	if ((r = read_8(&status)))
		return r;

	*pubkey = malloc(len);
	if (!*pubkey) {
		errno = ENOMEM;
		/* todo: should we read the stuff out of the device anyway,
		   byte-by-byte into a small buf? */
		return -1;
	}

	if ((r = read_data(*pubkey, len))){
		free(*pubkey);
		*pubkey = NULL;
		return r;
	}

	if ((r = secs_to_cal_finish(secsfd)))
		return r;
	 
 	return len;
}

/*
 * Delete an RSA key.
 * Return is zero for success or -1 for error; errno has details.
 */
int bb5_rsakp_delete(int set, int key)
{
	int r, secsfd;

	/* todo: obtain fd-mutex and release it in all cases */

	if ((r = open_device()))
		return r;

	secsfd = secs_to_cal_begin();
	if (secsfd < 0)
		return -1;


	if ((r = write_cmd(OMAP_SEC_CMD_RSAKP_DELETE, 1 + 1)))
		return r;

	if ((r = write_8(set)))
		return r;

	if ((r = write_8(key)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_RSAKP_DELETE)))
		return r;

	return secs_to_cal_finish(secsfd);
}

/*
 * Import an RSA key.
 * Returns zero for success or -1 for error; errno has details.
 */
int bb5_rsakp_import(const unsigned char *buf, size_t len)
{
	int r, secsfd;
	unsigned char status;

	/* todo: obtain fd-mutex and release it in all cases */

	if ((r = open_device()))
		return r;

	secsfd = secs_to_cal_begin();
	if (secsfd < 0)
		return -1;

	if ((r = write_cmd(OMAP_SEC_CMD_RSAKP_IMPORT, 4 + len)))
		return r;

	if ((r = write_32(len)))
		return r;

	if ((r = write_data(buf, len)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_RSAKP_IMPORT)))
		return r;

	/* todo: what should we do with status? */
	if ((r = read_8(&status)))
		return r;

	return secs_to_cal_finish(secsfd);
}

/*
 * RSA keypair sign/verify. Type of operation is passed in 'type'.
 * Allocates output buffer and returns it in *out.
 * Returns length of output or -1 for error; errno has details.
 */
static ssize_t rsakp_service(int type, int set, int key,
		const unsigned char *in, size_t len, unsigned char **out)
{
	int r;
	uint32_t out_len;

	fprintf(stderr, "libbb5: rsakp_service type %d\n", type);

	if (!out) {
		errno = EINVAL;
		return -1;
	}

	fprintf(stderr, "libbb5: rsakp_service #0.1\n");

	/* todo: obtain fd-mutex and release it in all cases */

	if ((r = open_device()))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #1\n");

	if ((r = write_cmd(OMAP_SEC_CMD_RSAKP_SERVICE, 2 + 1 + 1 + 4 + len)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #2\n");

	if ((r = write_16(type)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #3\n");

	if ((r = write_8(set)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #4\n");

	if ((r = write_8(key)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #5\n");

	if ((r = write_32(len)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #6\n");

	if ((r = write_data(in, len)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #7\n");

	if ((r = read_result(OMAP_SEC_CMD_RSAKP_SERVICE)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #8\n");

	if ((r = read_32(&out_len)))
		return r;

	fprintf(stderr, "libbb5: rsakp_service #9, output len %d\n", out_len);

	*out = malloc(out_len);
	if (!*out) {
		errno = ENOMEM;
		return -1;
	}

	fprintf(stderr, "libbb5: rsakp_service #10\n");

	if ((r = read_data(*out, out_len))) {
		free(*out);
		*out = NULL;
		return r;
	}

	fprintf(stderr, "libbb5: rsakp_service #11\n");

	return out_len;
}

/*
 * Sign msg using an RSA key. Allocates output buffer and returns it in
 * *signature. Returns length of output or -1 for error; errno has details.
 */
ssize_t bb5_rsakp_sign(int set, int key, const unsigned char *msg,
					size_t len, unsigned char **signature)
{
	syslog(LOG_NOTICE, "rsa sign with set %d, key %d\n", set, key);
	return rsakp_service(OMAP_SEC_RSAKP_TYPE_SIGN_PKCS1_v1_5,
						set, key, msg, len, signature);
}

/*
 * Decrypt msg using an RSA key. Allocates output buffer and returns it in
 * *plain. Returns length of output or -1 for error; errno has details.
 */
ssize_t bb5_rsakp_decrypt(int set, int key, const unsigned char *msg,
					size_t len, unsigned char **plain)
{
	syslog(LOG_NOTICE, "rsa decrypt with set %d, key %d\n", set, key);
	return rsakp_service(OMAP_SEC_RSAKP_TYPE_DECRYPT_PKCS1_v1_5,
						set, key, msg, len, plain);
}

/*
 * Query parameters of an RSA key stored as given keyset and key number.
 * Returns negative for error (f.ex. no key at given position), zero for
 * success. Pass in a pointer to struct bb5_key_info to receive more
 * information about the key.
 */
int bb5_rsakp_info(int set, int key, struct bb5_rsa_key_info **info)
{
	int r, i;
	uint8_t type, dummy[3];
	uint16_t size, services;
	uint32_t pub_exp;
	ssize_t size_bytes;

	if ((r = open_device()))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #1\n");

	if ((r = write_cmd(OMAP_SEC_CMD_RSAKP_KEY_INFO, 1 + 1)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #2\n");

	/* todo: what service should be used for info querying? */
	/* apparently no service parameter is needed after all?? */
	/*if ((r = write_16(0)))
		goto out;*/

	fprintf(stderr, "libbb5 keyinfo #3\n");

	if ((r = write_8(set)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #4\n");

	if ((r = write_8(key)))
		goto out;
	fprintf(stderr, "libbb5 keyinfo #5\n");


	if ((r = read_result(OMAP_SEC_CMD_RSAKP_KEY_INFO)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #6\n");

	if ((r = read_16(&size)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #7, size = 0x%04x\n", size);

	if ((r = read_16(&services)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #8, services = 0x%04x\n", services);

	if ((r = read_8(&type)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #8.1, type = 0x%02x\n", type);

	if ((r = read_data(dummy, 3)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #8.2, dummy = 0x%02x%02x%02x\n", dummy[0],
	dummy[1], dummy[2]);

	if ((r = read_32(&pub_exp)))
		goto out;

	fprintf(stderr, "libbb5 keyinfo #8.3, pub_exp = 0x%08x\n", pub_exp);

	size_bytes = size / 8;   /* key size is reported in bits */
	*info = malloc(sizeof(**info) + size_bytes);
	if (!*info) {
		errno = ENOMEM;
		r = -1;
		goto out;
	}

	fprintf(stderr, "libbb5 keyinfo #9\n");

	if ((r = read_data((*info)->modulus, size_bytes))) {
		free(*info);
		*info = NULL;
		goto out;
	}

	fprintf(stderr, "libbb5 keyinfo #10\n");

	(*info)->size = size;
	(*info)->services = services;
	(*info)->pub_exp = pub_exp;
	(*info)->type = type;

	/* PA outputs modulus LSB-first, convert to MSB-first */
	for (i = 0; i < size_bytes/2; i++) {
		uint8_t tmp;
		
		tmp = (*info)->modulus[i];
		(*info)->modulus[i] = (*info)->modulus[size_bytes - 1 - i];
		(*info)->modulus[size_bytes - 1 - i] = tmp;
	}

out:
	return r;
}

/*
 * Internal helper function to isolate the certificates' CAL block naming
 * format to one place.
 */
static void cert_block_name(bb5_cert_t id, size_t buflen, unsigned char *buf)
{
	snprintf(buf, buflen, "cert_%d", id);
}

/*
 * Store a certificate. Will overwrite any existing certificate with the
 * same id. Returns len for success, or a negative error code.
 */
ssize_t bb5_cert_store(bb5_cert_t id, const unsigned char *buf, size_t len)
{
	struct cal *cal;
	char blockname[16];
	ssize_t r = len;

	if (cal_init(&cal) < 0) {
		errno = EIO;
		return -1;
	}

	cert_block_name(id, sizeof(blockname), blockname);

	if (cal_write_block(cal, blockname, buf, len, CAL_FLAG_USER) < 0) {
		errno = EIO;
		r = -1;
	}

	cal_finish(cal);
	return r;
}

static const char const *cert_names[] =
{
	"CCC",
	"NPC",
	"HWC",
	"X509",
};

static void cert_id_name(bb5_cert_t id, char *buf, int len)
{
	if ((id >= 0) && (id < ARRAY_SIZE(cert_names)))
		strncpy(buf, cert_names[id], len);

	snprintf(buf, len, "unknown %d", id);
}

/*
 * Read a certificate previously stored with given id. Allocates buffer
 * and returns its address in *buf. Returns length of data in *buf or a
 * negative error code.
 */
ssize_t bb5_cert_read(bb5_cert_t id, unsigned char **buf)
{
	struct cal *cal;
	char blockname[16];
	ssize_t r;
	unsigned long len;
	char certname[50];

	cert_id_name(id, certname, sizeof(certname));
	syslog(LOG_INFO, "read cert from CAL: %s\n", certname);

	if (cal_init(&cal) < 0) {
		errno = EIO;
		return -1;
	}

	cert_block_name(id, sizeof(blockname), blockname);

	if (cal_read_block(cal, blockname, (void **) buf, &len, CAL_FLAG_USER)
	    < 0) {
		errno = EIO;
		r = -1;
	}
	else
		r = len;

	cal_finish(cal);
	return r;
}

/*
 * Delete a certificate. Returns zero if it was successfully deleted, or there
 * wasn't a certificate stored with given id. Returns negative error code
 * if deletion failed.
 */
int bb5_cert_delete(bb5_cert_t id)
{
	struct cal *cal;
	char blockname[16];
	void *buf;
	unsigned long len;
	int ret = 0;
	char certname[50];

	cert_id_name(id, certname, sizeof(certname));
	syslog(LOG_INFO, "delete cert from CAL: %s\n", certname);

	if (cal_init(&cal) < 0) {
		errno = EIO;
		return -1;
	}

	cert_block_name(id, sizeof(blockname), blockname);

	/*
	 * libcal doesn't actually have a record deletion function, so we check
	 * if the certificate exists and overwrite it with zeros. Thus, after
	 * deletion of an existing certificate, it still can be 'read'; it will
	 * just contain zeros. This will reveal the length of the old
	 * certificate...
	 */

	if (cal_read_block(cal, blockname, &buf, &len, CAL_FLAG_USER) >= 0) {
		memset(buf, 0, len);
		ret = cal_write_block(cal, blockname, buf, len, CAL_FLAG_USER);
	}
	else {
		/* The cert wasn't there, so we needn't do anything. */
	}

	cal_finish(cal);
	return ret;
}

int bb5_bxp_import(const unsigned char *blob, size_t blen, unsigned char **hout)
{
	int r, secsfd;
	uint8_t output[32];

	if ((!blob) || (blen <= 0)) {
		errno = EINVAL;
		return -1;
	}

	if ((r = open_device()))
		return r;

	secsfd = secs_to_cal_begin();
	if (secsfd < 0)
		return -1;

	if ((r = write_cmd(OMAP_SEC_CMD_BXP_IMPORT, blen)))
		return r;

	if ((r = write_data(blob, blen)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_BXP_IMPORT)))
		return r;

	if ((r = read_data(output, sizeof(output))))
		return r;

	if ((r = secs_to_cal_finish(secsfd)))
		return r;

	if (hout) {
		*hout = malloc(sizeof(output));
		if (!*hout)
			return -1;

		memcpy(*hout, output, sizeof(output));
	}

	return sizeof(output);
}

int bb5_bxp_export(unsigned char **key)
{
	int r;
	uint8_t output[16];

	if ((r = open_device()))
		return r;

	if ((r = write_cmd(OMAP_SEC_CMD_BXP_EXPORT, 0)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_BXP_EXPORT)))
		return r;

	if ((r = read_data(output, sizeof(output))))
		return r;

	if (key) {
		*key = malloc(sizeof(output));
		if (!*key)
			return -1;

		memcpy(*key, output, sizeof(output));
	}

	return sizeof(output);
}

int bb5_sd_prod_init(const unsigned char *blob, size_t len)
{
	int r, secsfd;

	if ((!blob) || ( len <= 0)) {
		errno = EINVAL;
		return -1;
	}

	if ((r = open_device()))
		return r;

	secsfd = secs_to_cal_begin();
	if (secsfd < 0)
		return -1;

	if ((r = write_cmd(OMAP_SEC_CMD_SD_PROD_INIT, len)))
		return r;

	if ((r = write_data(blob, len)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_SD_PROD_INIT)))
		return r;

	return secs_to_cal_finish(secsfd);
}

int bb5_sd_auth_init(unsigned char *session, unsigned char *chip,
		     bb5_auth_algo_t *algo)
{
	int r;
	uint8_t sessionid[16];
	uint8_t chipid[20];
	uint8_t a;
	uint8_t dummy[3];

	if ((r = open_device()))
		return r;

	if ((r = write_cmd(OMAP_SEC_CMD_SD_AUTH_INIT, 0)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_SD_AUTH_INIT)))
		return r;

	if ((r = read_data(sessionid, sizeof(sessionid))))
		return r;

	if ((r = read_data(chipid, sizeof(chipid))))
		return r;

	if ((r = read_8(&a)))
		return r;

	if ((r = read_data(dummy, sizeof(dummy))))
		return r;

	if (session)
		memcpy(session, sessionid, sizeof(sessionid));

	if (chip)
		memcpy(chip, chipid, sizeof(chipid));

	if (algo)
		*algo = a;

	return 0;
}

int bb5_sd_auth(int msgid, struct bb5_sd_info *sdinfo, int session2,
		const unsigned char *mac, unsigned char **resp)
{
	int r;
	uint8_t respbuf[24];
	uint8_t tempbuf[24];

	if ((!sdinfo) || (!mac)) {
		errno = EINVAL;
		return -1;
	}

	if ((r = open_device()))
		return r;

	if ((r = write_cmd(OMAP_SEC_CMD_SD_AUTH, 24)))
		return r;

	if ((r = write_8(msgid)))
		return r;

	if ((r = write_data(sdinfo->type, 2)))
		return r;

	if ((r = write_data(sdinfo->serial, 6)))
		return r;

	if ((r = write_data(sdinfo->expdate, 3)))
		return r;

	if ((r = write_32(session2)))
		return r;

	if ((r = write_data(mac, 8)))
		return r;

	if ((r = read_result(OMAP_SEC_CMD_SD_AUTH)))
		return r;

	/* Use respbuf as a dummy buffer first */
	if ((r = read_data(respbuf, 12)))
		return r;

	if ((r = read_data(respbuf, sizeof(respbuf))))
		return r;

	if ((r = read_data(tempbuf, sizeof(tempbuf))))
		return r;
	
	if (resp) {
		*resp = malloc(sizeof(respbuf));
		if (!*resp)
			return -1;
		
		memcpy(*resp, respbuf, sizeof(respbuf));
		return sizeof(respbuf);
	}

	return 0;
}

int bb5_sd_verify(const unsigned char *msg, const unsigned char *mac)
{
	int r;

	if ((r = open_device()))
		return r;

	if ((r = write_cmd(OMAP_SEC_CMD_SD_VERIFY, 16 + 8)))
		return r;

	if ((r = write_data(msg, 16)))
		return r;

	if ((r = write_data(mac, 8)))
		return r;

	return read_result(OMAP_SEC_CMD_SD_VERIFY);
}
