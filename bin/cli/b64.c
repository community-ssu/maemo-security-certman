/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include <maemosec_common.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LLEN 76

enum {encode, decode} mode = encode;

static void
usage(void)
{
	printf("%s\n", "Usage: b64 [-e|-b] <file>");
}

int main(int argc, char* argv[])
{
	int a, fd;
	unsigned char *data;
	char *edata, *c;
	ssize_t len, flen;
	struct stat fs;

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
		default:
			usage();
			exit(0);
		}
	}

	if (optind == argc) {
		usage();
		exit(0);
	}

	fd = open(argv[optind], O_RDONLY);
	if (0 > fd) {
		MAEMOSEC_ERROR("cannot open '%s' (%s)\n",
					   argv[optind], strerror(errno));
		exit(0);
	}

	fstat(fd, &fs);
	flen = len = fs.st_size;
	data = (unsigned char*)mmap(NULL, flen, PROT_READ, MAP_PRIVATE, fd, 0);

	if (MAP_FAILED == data) {
		close(fd);
		MAEMOSEC_ERROR("cannot map '%s' (%s)\n",
					   argv[optind], strerror(errno));
		exit(0);
	}

	if (encode == mode) {
		edata = base64_encode(data, len);
		if (NULL == edata) {
			close(fd);
			MAEMOSEC_ERROR("cannot encode '%s' (%s)\n",
						   argv[optind], strerror(errno));
			exit(0);
		}
		len = strlen(edata);
		for (c = edata; len > LLEN; len -= LLEN) {
			char lbuf[LLEN + 1];
			memmove(lbuf, c, LLEN);
			lbuf[LLEN] = '\0';
			printf("%s\n", lbuf);
			c += LLEN;
		}
		printf("%s\n", c);

	} else {
		unsigned char* buf;
		len = base64_decode((char*)data, &buf);
		printf("%s", (char*)buf);
		free(buf);
	}

	munmap(data, flen);
	close(fd);
	return(0);
}
