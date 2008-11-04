/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>

#define DLOG_PORT htons(2300)
#define INET4A(a,b,c,d) (in_addr_t)htonl(a << 24 | b << 16 | c << 8 | d)

/*
 * TODO: This code is not thread safe
 */

void
dlog_message(const char* format, ...)
{
	static struct sockaddr_in i_mad, i_rad;
	static int dlog_socket = -1;
	static char sndbuf [1024];
	va_list p_arg;
	int rc;
	size_t printed;

	if (dlog_socket == -1) {
		dlog_socket = socket(PF_INET, SOCK_DGRAM, 0);
		if (dlog_socket < 0)
			return;
		i_mad.sin_family = i_rad.sin_family = AF_INET;
		i_mad.sin_addr.s_addr = INADDR_ANY;
		i_mad.sin_port = 0;
		/*
		 * TODO: Obviously...
		 */
		i_rad.sin_addr.s_addr = INET4A(192,168,2,1);
		i_rad.sin_port = DLOG_PORT;
		rc = bind(dlog_socket, (struct sockaddr*)&i_mad, sizeof(struct sockaddr_in));
		if (rc < 0) {
			close(dlog_socket);
			dlog_socket = -1;
			return;
		}
	}
	
	va_start(p_arg, format);
	printed = vsnprintf(sndbuf, sizeof(sndbuf) - 1, format, p_arg);
	va_end(p_arg);
	rc = sendto(dlog_socket, sndbuf, printed, MSG_DONTWAIT, 
				(struct sockaddr*)&i_rad, 
				sizeof(struct sockaddr_in));
}
