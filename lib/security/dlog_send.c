/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <maemosec_common.h>

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
	static unsigned long s_addr = (unsigned long)-1;
	va_list p_arg;
	int rc, port;
	size_t printed;

	if (dlog_socket == -1) {
		dlog_socket = socket(PF_INET, SOCK_DGRAM, 0);
		if (dlog_socket < 0) {
			syslog(LOG_ERR, "%s(%d)[%s]: ERROR cannot create debug socket (%d)\n",
				   __FILE__, __LINE__, __func__, errno);
			return;
		}
#if 0
		i_mad.sin_family = AF_INET;
		i_mad.sin_addr.s_addr = INADDR_ANY;
		i_mad.sin_port = 0;
		rc = bind(dlog_socket, (struct sockaddr*)&i_mad, sizeof(struct sockaddr_in));
		if (rc < 0) {
			syslog(LOG_ERR, "%s(%d)[%s]: ERROR cannot bind debug socket (%d)\n",
				   __FILE__, __LINE__, __func__, errno);
			close(dlog_socket);
			dlog_socket = -1;
			return;
		} else {
			syslog(LOG_INFO, "%s(%d)[%s]: bound debug socket to port %d\n",
				   __FILE__, __LINE__, __func__, ntohs(i_mad.sin_port));
		}
#endif
	}
	/*
	 * TODO: Obviously...
	 */
	if ((unsigned long)-1 == s_addr) {
		int i1, i2, i3, i4, p, rc;
		char* addr = GETENV("DLOG_TARGET","127.0.0.1");
		rc = sscanf(addr, "%d.%d.%d.%d:%d", &i1, &i2, &i3, &i4, &p);
		if (rc >= 4) {
			s_addr = INET4A(i1,i2,i3,i4);
			if (rc == 5)
				port = p;
			else
				port = 2300;
		}
	}
	i_rad.sin_family = AF_INET;
	i_rad.sin_addr.s_addr = s_addr;
	i_rad.sin_port = htons(port);
	va_start(p_arg, format);
	printed = vsnprintf(sndbuf, sizeof(sndbuf) - 1, format, p_arg);
	va_end(p_arg);
	rc = sendto(dlog_socket, sndbuf, printed, MSG_DONTWAIT, 
				(struct sockaddr*)&i_rad, 
				sizeof(struct sockaddr_in));
	if (rc < 0) {
		syslog(LOG_ERR, "%s(%d)[%s]: ERROR cannot send debug message (%d)\n",
			   __FILE__, __LINE__, __func__, errno);
	}
}
