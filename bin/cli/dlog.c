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

#define DLOG_PORT htons(2300)

#define INET4A(a,b,c,d) (in_addr_t)htonl(a << 24 | b << 16 | c << 8 | d)

static char recbuf [1024];

int 
main(int argc, char* argv[])
{
	int sd, rc, port = 2300;
	size_t rlen;
	char arg;
	char* msg = NULL;
	struct sockaddr_in i_mad, i_rad;

	if (argc < 2) {
		fprintf(stderr, "Usage: dlog [-l port] [-s message]\n");
	}

	while ((arg = getopt(argc, argv, "l:s:")) >= 0) {
		switch (arg) {
		case 'l':
			port = atoi(optarg);
			break;
		case 's':
			msg = optarg;
			break;
		default:
			;
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
		i_rad.sin_addr.s_addr = INET4A(192,168,2,1);
		i_rad.sin_port = DLOG_PORT;
	} else {
		// Receive
		i_rad.sin_addr.s_addr = INADDR_ANY;
		i_mad.sin_addr.s_addr = INET4A(192,168,2,1);
		i_mad.sin_port = DLOG_PORT;
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
		time_t tt_now;
		struct tm* t_now;
		while (1) {
			rlen = sizeof(struct sockaddr_in);
			rc = recvfrom(sd, recbuf, sizeof(recbuf) - 1, 0, 
						  (struct sockaddr*)&i_rad, 
						  &rlen);
			if (rc < 0) {
				fprintf(stderr, "Error from recvfrom (%d)\n", errno);
				break;
			}
			gettimeofday(&now, NULL);
			time(&tt_now);
			t_now = localtime(&tt_now);
			recbuf[rc] = '\0';
			printf("%04d-%02d-%02dT%02d:%02d:%02d.%06ld %s\n", 
				   t_now->tm_year + 1900, t_now->tm_mon + 1, t_now->tm_mday,
				   t_now->tm_hour, t_now->tm_min, t_now->tm_sec, now.tv_usec,
				   recbuf);
		}
	}

	close(sd);

	return(0);
}
