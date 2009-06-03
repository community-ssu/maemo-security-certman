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

#define LLEN 64

enum {encode, decode} mode = encode;

static void
usage(void)
{
	printf("%s\n", "Usage: b64 [-e(ncode)|-d(ecode)] <file> [-o <outfile>]");
}

int main(int argc, char* argv[])
{
	int a, fd, ofd = -1;
	unsigned char *data;
	char *edata, *c;
	ssize_t len, flen, wlen;
	struct stat fs;

    while (1) {
		a = getopt(argc, argv, "edo:");
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
		case 'o':
			ofd = open(optarg, O_CREAT | O_RDWR, 0644);
			if (0 > ofd) {
				fprintf(stderr, "ERROR: cannot open '%s' (%s)\n",
						optarg, strerror(errno));
				exit(-1);
			}
			MAEMOSEC_DEBUG(1, "Output file %ld", ofd);
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
		if (-1 == ofd) {
			for (c = edata; len > LLEN; len -= LLEN) {
				char lbuf[LLEN + 1];
				memmove(lbuf, c, LLEN);
				lbuf[LLEN] = '\0';
				printf("%s\n", lbuf);
				c += LLEN;
			}
			printf("%s\n", c);
		} else {
			wlen = write(ofd, data, len);
			if (wlen != len)
				fprintf(stderr, "ERROR: %s (written %ld != tried %ld)\n", 
						strerror(errno), wlen, len);
			close(ofd);
		}

	} else {
		unsigned char* buf;
		len = base64_decode((char*)data, &buf);
		MAEMOSEC_DEBUG(1, "Decoded %ld bytes, %p write to %d", len, buf, ofd);
		if (-1 == ofd) {
			printf("%s", (char*)buf);
		} else {
			wlen = write(ofd, buf, len);
			if (wlen != len)
				fprintf(stderr, "ERROR: %s (written %ld != tried %ld)\n", 
						strerror(errno), wlen, len);
			close(ofd);
		}
		free(buf);
	}

	munmap(data, flen);
	close(fd);
	return(0);
}
