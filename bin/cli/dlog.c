/* -*- mode:c; tab-width:4; c-basic-offset:4; -*-
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

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <syslog.h>
#include <signal.h>

#define INET4A(a,b,c,d) (in_addr_t)htonl(a << 24 | b << 16 | c << 8 | d)

static char recbuf [0x4000];
static int interrupted = 0;
static int sd = -1;
static long rnbr = -1;

void interrupt(int sign)
{
	fprintf(stderr, "Int %d\n", sign);
	if (-1 != sd)
		close(sd);
	sd = -1;
	interrupted = 1;
}

int 
main(int argc, char* argv[])
{
	int i1 = 127, i2 = 0, i3 = 0, i4 = 1, port = 2300;
	int rc, level = 9;
	int run_as_daemon = 0, silent = 0;
	int ofd = -1;
	socklen_t slen;
	signed char arg;
	struct sockaddr_in i_mad, i_rad;
	long onbr;

	while ((arg = getopt(argc, argv, "l:a:o:ds")) >= 0) {
		switch (arg) {
		case 'l':
			level = atoi(optarg);
			break;
		case 'a':
			rc = sscanf(optarg, "%d.%d.%d.%d:%d", &i1, &i2, &i3, &i4, &port);
			if (rc < 4) {
				fprintf(stderr, "Invalid IPv4 address '%s'\n",
						optarg);
				return(-1);
			}
			break;
		case 'd':
			run_as_daemon = 1;
			openlog("dlog", 0, LOG_DAEMON);
			if (0 > (rc = daemon(0, 0)))
				fprintf(stderr, "Failed to daemonize (%s)\n", strerror(errno));
			break;
		case 'o':
			ofd = open(optarg, O_APPEND | O_WRONLY | O_CREAT, 0644);
			if (-1 == ofd) {
				fprintf(stderr, "Cannot open '%s' (%s)\n", optarg, strerror(errno));
				return(-1);
			}
			break;
		case 's':
			silent = 1;
			break;
		default:
			fprintf(stderr, "Usage: dlog -d [-a address-to-listen:port-to-listen]"
					" [-l level] [-o outfile]\n");
			return(-1);
		}
	}

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		fprintf(stderr, "Cannot create socket (%d)\n", errno);
		return(-1);
	}

	/*
	 * Make the input buffer rather big
	 */
	{
		unsigned rec_buffer_size = 64 * 1024;
		setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rec_buffer_size, 
				   sizeof(rec_buffer_size));
	}

	memset(&i_mad, '\0', sizeof(i_mad));
	i_mad.sin_family = i_rad.sin_family = AF_INET;
	i_mad.sin_port = i_rad.sin_port = 0;
	i_rad.sin_addr.s_addr = INADDR_ANY;
	i_mad.sin_addr.s_addr = INET4A(i1, i2, i3, i4);
	i_mad.sin_port = htons(port);
	
	rc = bind(sd, (struct sockaddr*)&i_mad, sizeof(struct sockaddr_in));
	if (rc < 0) {
		fprintf(stderr, "Cannot bind socket (%d)\n", errno);
		return(-1);
	}

	signal(SIGINT, interrupt);
	{
		struct timeval now;
		struct tm* t_now;
		struct timeval prev_stamp = {0, 0};
		char time_as_str [64];
		int dlevel;
		char* c;

		printf("Listening %d.%d.%d.%d:%d...\n", i1, i2, i3, i4, port);

#define ONBR_OFF 4

		while (!interrupted) {
			slen = sizeof(struct sockaddr_in);
			rc = recvfrom(sd, recbuf, sizeof(recbuf) - 1, 0, 
						  (struct sockaddr*)&i_rad, 
						  &slen);
			if (rc < 0) {
				fprintf(stderr, "Error from recvfrom (%d)\n", errno);
				break;
			}
			if (rc < ONBR_OFF + 3)
				continue;

			memcpy(&onbr, recbuf, sizeof(onbr));
			if (rnbr != -1 && (rnbr + 1) < onbr) {
				printf(">>> lost %ld from %ld to %ld\n", onbr - rnbr - 1, rnbr + 1, onbr - 1);
			} 
			rnbr = onbr;

			recbuf[rc] = '\0';
			if (recbuf[ONBR_OFF] == '<' && recbuf[ONBR_OFF + 2] == '>') {
				dlevel = recbuf[ONBR_OFF + 1] - '0';
				if (dlevel > level)
					continue;
			} else
				dlevel = 0;

			gettimeofday(&now, NULL);
			if (now.tv_sec > prev_stamp.tv_sec + 10) {
				t_now = localtime(&now.tv_sec);
				sprintf(time_as_str, "%04d-%02d-%02d %02d:%02d:%02d.%06ld ", 
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
				sprintf(time_as_str, "%16s+%02ld.%06ld ", "", diff_sec, diff_usec);
			}

			c = recbuf + ONBR_OFF + 3;

			if (!run_as_daemon) {

				if (-1 != ofd) {
					ssize_t written;
					written = write(ofd, time_as_str, strlen(time_as_str));
					written += write(ofd, c, strlen(c));
					written += write(ofd, "\n", 1);
				}

				if (!silent) {
					printf("%s", time_as_str);

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

			} else {
				syslog(LOG_ERR + dlevel, "%s %s", time_as_str, c);
			}
		}
	}

	if (-1 != ofd)
		close(ofd);
	if (-1 != sd)
		close(sd);
	if (run_as_daemon)
		closelog();
	return(0);
}
