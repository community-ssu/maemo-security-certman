/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>

#define INET4A(a,b,c,d) (in_addr_t)htonl(a << 24 | b << 16 | c << 8 | d)

static char recbuf [1024];

int 
main(int argc, char* argv[])
{
	int i1 = 127, i2 = 0, i3 = 0, i4 = 1, port = 2300;
	int sd, rc, level = 9;
	size_t rlen;
	char arg;
	char* msg = NULL;
	struct sockaddr_in i_mad, i_rad;

	while ((arg = getopt(argc, argv, "l:s:a:")) >= 0) {
		switch (arg) {
		case 'l':
			level = atoi(optarg);
			break;
		case 's':
			msg = optarg;
			break;
		case 'a':
			rc = sscanf(optarg, "%d.%d.%d.%d:%d", &i1, &i2, &i3, &i4, &port);
			if (rc < 4) {
				fprintf(stderr, "Invalid IPv4 address '%s'\n",
						optarg);
				return(-1);
			}
			break;
		default:
			fprintf(stderr, "Usage: dlog [-l level] [-s message]\n");
			return(-1);
		}
	}

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		fprintf(stderr, "Cannot create socket (%d)\n", errno);
		return(-1);
	}

	i_mad.sin_family = i_rad.sin_family = AF_INET;
	i_mad.sin_port = i_rad.sin_port = 0;
	if (msg) {
		// Send
		i_mad.sin_addr.s_addr = INADDR_ANY;
		i_rad.sin_addr.s_addr = INET4A(i1, i2, i3, i4);
		i_rad.sin_port = htons(port);
	} else {
		// Receive
		i_rad.sin_addr.s_addr = INADDR_ANY;
		i_mad.sin_addr.s_addr = INET4A(i1, i2, i3, i4);
		i_mad.sin_port = htons(port);
	}
	
	rc = bind(sd, (struct sockaddr*)&i_mad, sizeof(struct sockaddr_in));
	if (rc < 0) {
		fprintf(stderr, "Cannot bind socket (%d)\n", errno);
		return(-1);
	}

	if (msg) {
		rc = sendto(sd, msg, strlen(msg), MSG_DONTWAIT, 
					(struct sockaddr*)&i_rad, 
					sizeof(struct sockaddr_in));
		if (rc < 0) {
			fprintf(stderr, "Error from sendto (%d)\n", errno);
		}
	} else {
		struct timeval now;
		struct tm* t_now;
		struct timeval prev_stamp = {0, 0};
		int dlevel;
		char* c;

		printf("Listening %d.%d.%d.%d:%d...\n", i1, i2, i3, i4, port);

		while (1) {
			rlen = sizeof(struct sockaddr_in);
			rc = recvfrom(sd, recbuf, sizeof(recbuf) - 1, 0, 
						  (struct sockaddr*)&i_rad, 
						  &rlen);
			if (rc < 0) {
				fprintf(stderr, "Error from recvfrom (%d)\n", errno);
				break;
			}
			if (rc < 3)
				continue;

			recbuf[rc] = '\0';
			if (recbuf[0] == '<' && recbuf[2] == '>') {
				dlevel = recbuf[1] - '0';
				if (dlevel > level)
					continue;
			}

			gettimeofday(&now, NULL);
			if (now.tv_sec > prev_stamp.tv_sec + 10) {
				t_now = localtime(&now.tv_sec);
				printf("%04d-%02d-%02d %02d:%02d:%02d.%06ld ", 
					   t_now->tm_year + 1900, t_now->tm_mon + 1, t_now->tm_mday,
					   t_now->tm_hour, t_now->tm_min, t_now->tm_sec, now.tv_usec);
				prev_stamp = now;
			} else {
				time_t diff_sec;
				suseconds_t diff_usec;
				if (now.tv_usec < prev_stamp.tv_usec) {
					diff_sec  = now.tv_sec - 1 - prev_stamp.tv_sec;
					diff_usec = 1000000 + now.tv_usec - prev_stamp.tv_usec;
				} else {
					diff_sec  = now.tv_sec - prev_stamp.tv_sec;
					diff_usec = now.tv_usec - prev_stamp.tv_usec;
				}
				printf("%16s+%02ld.%06ld ", "",
					   diff_sec, diff_usec);
			}
			c = recbuf + 3;
			while ( c && *c ) {
				char* a;
				if (*c == '\n') {
					if (*(c + 1)) {
						printf("\n%27s", "");
						c++;
					} else {
						printf("%c", '\n');
						break;
					}
				}
				for (a = c; *a && ('\n' != *a); a++)
					printf("%c", *a);
				c = a;
			}
			if ('\n' != *c)
				printf("%c", '\n');
		}
	}

	close(sd);
	return(0);
}
