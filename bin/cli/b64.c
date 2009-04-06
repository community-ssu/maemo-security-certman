/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAEMOSEC_ERROR(s) do { \
	fprintf(stderr, "%s\n", s); \
	exit(0); \
} while(0)

/*
 * Help routines
 */
const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

static char*
base64_encode(unsigned char* data, unsigned len)
{
	unsigned char* b;
	char *res = malloc((4*len)/3 + len%3 + 1);
	char *c = res;
	int bytes_left = (int)len;

	for (b = data, data += len; 0 < bytes_left; b += 3) {
		switch (bytes_left) 
			{
			case 1:
				*c++ = b64t[*b & 0xfc >> 2];
				*c++ = b64t[*b & 0x03 << 4];
				*c++ = '=';
				*c++ = '=';
				break;
			case 2:
				*c++ = b64t[*b & 0xfc >> 2];
				*c++ = b64t[(*b & 0x03 << 4) | (*(b + 1) & 0xf0 >> 4)];
				*c++ = b64t[*(b + 1) & 0x0f << 2];
				*c++ = '=';
				break;
			default:
				*c++ = b64t[*b & 0xfc >> 2];
				*c++ = b64t[(*b & 0x03 << 4) | (*(b + 1) & 0xf0 >> 4)];
				*c++ = b64t[(*(b + 1) & 0x0f << 2) | (*(b + 2) & 0xc0 >> 6)];
				*c++ = b64t[*(b + 2) & 0x3f];
				break;
			}
		bytes_left -= 3;
	}
	*c = '\0';
	return(res);
}

static unsigned
base64_decode(char* string, unsigned char** to_buf)
{
	char *c = string;
	char s[4];
	unsigned len, i, done = 0;
	unsigned char *b;

	*to_buf = NULL;
	if (NULL == c)
		return(0);
	len = strlen(c)*3;
	if (len % 4) {
		MAEMOSEC_ERROR("Invalid base64 string");
		return(0);
	}
	len >>= 2;
	*to_buf = b = malloc(len);
	for (c = string; *c && 0 == done; c += 4) {
		memcpy(s, c, 4);
		for (i = 0; i < 4; i++) {
			if ('=' == s[i]) {
				s[i] = 0;
				if (3 == i) {
					len -= 1;
					done = 1;
				} else if (2 == i) {
					len -= 2;
					done = 1;
				} else {
					goto error;
				}
			} else if ('+' == s[i])
				s[i] = 62;
			else if ('/' == s[i])
				s[i] = 63;
			else if ('a' <= s[i] && 'z' >= s[i])
				s[i] = 26 + s[i] - 'a';
			else if ('A' <= s[i] && 'Z' >= s[i])
				s[i] = s[i] - 'A';
			else if ('0' <= s[i] && '9' >= s[i])
				s[i] = 52 + s[i] - '0';
			else {
			error:
				MAEMOSEC_ERROR("Invalid base64 string");
				free(*to_buf);
				*to_buf = NULL;
				return(0);
			}
		}
		*b++ = (s[0] << 2) | (s[1] & 0xc >> 4);
		*b++ = (s[1] & 0x0f << 4) | (s[2] & 0x3c >> 4);
		*b++ = (s[2] & 0x03 << 6) | (s[3]);
	}
	return(len);
}

enum {encode, decode} mode = encode;

int main(int argc, char* argv[])
{
	int a, i;
	unsigned len;

    while (1) {
		a = getopt(argc, argv, "ed");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
		case 'e':
			mode = encode;
			break;
		case 'd':
			mode = decode;
			break;
		}
	}

	for (i = optind; i < argc; i++) {
		if (encode == mode)
			printf("%s\n", base64_encode((unsigned char*)argv[i], strlen(argv[i])));
		else {
			unsigned char* buf;
			len = base64_decode(argv[i], &buf);
			printf("%s\n", (char*)buf);
			free(buf);
		}
	}

	return(0);
}
