// ------------------------------------------------------------------------
/// \file c_fstring.cpp
/// \brief The implementation of the c_fstring class
//
// Revision $Id: c_fstring.cpp,v 1.7 2005/12/19 18:02:44 a2vepsal Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#include "c_fstring.h"
#include "sec_common.h"

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>


c_fstring :: c_fstring ()
{
  str_buf = NULL;
  str_buf_len = 0;
  xml_buf = NULL;
  xml_buf_len = 0;
}


c_fstring :: c_fstring (c_fstring& model)
{
  str_buf = NULL;
  str_buf_len = 0;
  xml_buf = NULL;
  xml_buf_len = 0;
  if (model.str_buf)
    append(model.str_buf);
}


c_fstring :: c_fstring (const char* ini_value)
{
  // Only allocate the needed amount of bytes, because initialized
  // fstring usually do not grow
  if (ini_value && strlen(ini_value)) {
    str_buf_len = strlen(ini_value) + 1;
    str_buf = (char*)malloc(str_buf_len);
    strcpy(str_buf, ini_value);
    // __DEBUG(("init %p (%s)", str_buf, str_buf));
  } else {
    str_buf = NULL;
    str_buf_len = 0;
  };
  xml_buf = NULL;
  xml_buf_len = 0;
}


c_fstring :: c_fstring (const char* ini_value, int len)
{
  if (ini_value && len) {
    // Only allocate the needed amount of bytes, because initialized
    // fstring usually do not grow
    str_buf_len = len + 1;
    str_buf = (char*)malloc(str_buf_len);
    memcpy(str_buf, ini_value, len);
    *(str_buf + len) = '\0';
    // __DEBUG(("init %p (%s)", str_buf, str_buf));
  } else {
    str_buf = NULL;
    str_buf_len = 0;
  };
  xml_buf = NULL;
  xml_buf_len = 0;
}


c_fstring :: ~c_fstring ()
{
  if (str_buf) {
    // __DEBUG(("free %p (%s)", str_buf, str_buf));
    free(str_buf);
  };
  if (xml_buf)
    free(xml_buf);
  str_buf = NULL;
  str_buf_len = 0;
  xml_buf = NULL;
  xml_buf_len = 0;
}


char* c_fstring :: make_room (char** buf, int* len, int for_bytes, bool str_inited)
{
  int need_len, loc_len = *len;
  char* swap;
  char* cpy_to;

  if (str_inited) 
    need_len = strlen(*buf) + for_bytes;
  else
    need_len = for_bytes;

  if (need_len > loc_len) {
    // Make room for more data
    // Allocate in two's exponents to prevent fragmentation,
    // starting from 16 bytes
    loc_len = 0x10;
    while (loc_len < need_len)
      loc_len <<= 1;

    // DEBUG
    // printf ("c_sftring:make_room, need %d, have %d, alloc new %d\n", need_len, *len, loc_len);

    *len = loc_len;

    if (str_inited) {
      swap = (char*) malloc(loc_len);
      strcpy (swap, *buf);
      cpy_to = swap + strlen(swap);
      free(*buf);
      *buf = swap;
      swap = NULL;
    } else {
      *buf = (char*) malloc(loc_len);
      cpy_to = *buf;
    };
  } else
    cpy_to = *buf + strlen(*buf);

  // __DEBUG(("malloc %p", cpy_to));
  return cpy_to;
}


void c_fstring :: append (const char* data, int len)
{
	char* cpy_to = NULL;
  	cpy_to = make_room (&str_buf, &str_buf_len, len + 1, (str_buf != NULL));
  	memcpy (cpy_to, data, len);
  	*(cpy_to + len) = '\0';
}


void c_fstring :: append (const char* data)
{
  append (data, strlen(data));
}


void c_fstring :: append (char c, int repeat)
{
  char* cpy_to = make_room (&str_buf, &str_buf_len, repeat + 1, (str_buf != NULL));

  for (int i = 0; i < repeat; i++)
    *cpy_to++ = c;
  *cpy_to = '\0';
}


void c_fstring :: append(int maxlen, const char* format,...)
{
  va_list pArg;
  char small_buf [256];
  char* long_buf;

  va_start (pArg, format);
  if (maxlen < (int)sizeof(small_buf)) {
    vsnprintf(small_buf, maxlen + 1, format, pArg);
    append(small_buf);
  } else {
    long_buf = (char*)malloc(maxlen + 1);
    vsnprintf(long_buf, maxlen + 1, format, pArg);
    append(long_buf);
    free(long_buf);
  };
  va_end (pArg);
}


void c_fstring :: append_msg (const char* format,...)
{
  va_list pArg;
  char small_buf [256];

  va_start (pArg, format);
  vsnprintf(small_buf, sizeof(small_buf), format, pArg);
  append(small_buf);
  va_end (pArg);
}


#define _FBUF_SIZE 4096

void c_fstring :: append_file (const char* file_name)
{
  int fd, alen;
  char* buf = (char*) malloc(_FBUF_SIZE);

  fd = open(file_name, O_RDONLY);
  if (fd != -1) {
    do {
      alen = read(fd, buf, _FBUF_SIZE);
      if (alen > 0)
	append (buf, alen);
    } while (alen > 0);
    close(fd);
  };

  free(buf);

  if (!fd) {
    ERROR("file '%s' cannot be opened for reading (%d)",
		 file_name, errno);
  };
}


void c_fstring :: reset ()
{
  if (str_buf)
    free(str_buf);
  str_buf = NULL;
  str_buf_len = 0;
  if (xml_buf)
    free(xml_buf);
  xml_buf = NULL;
  xml_buf_len = 0;
}


void c_fstring :: remove (int start_point, int nbrof_chars)
{
  int len;
  if (str_buf) {
    len = strlen(str_buf);
    if (start_point + nbrof_chars > len)
      if (start_point >= len) {
		  ERROR("remove out-of-bounds, start-pos %d >= length %d", 
				start_point, len);
	return;
      } else
	nbrof_chars = len - start_point;
    memmove (str_buf + start_point, str_buf + start_point + nbrof_chars, 
	     len - (start_point + nbrof_chars) + 1);
      
  };
}


const char* c_fstring :: as_string()
{
  if (str_buf)
    return str_buf;
  else
    return "";
}

// These characters should be escaped in XML. The escape-strings are
// in corresponding positions in the second array
static const char  esc_chars [] = "<>&'\"";
static const char* esc_repls [] = {"lt", "gt", "amp", "apos", "quot"};

const char* c_fstring :: as_xml_string()
{
  if (str_buf) {
    int need_len = 0;
    char* d;
    char* ch;
    // Count how many bytes are needed
    for (ch = str_buf; *ch; ch++) {
      d = strpbrk(ch, esc_chars);
      if (d == NULL) {
	need_len += strlen(ch);
	break;
      } else {
	need_len += (d - ch) + strlen(esc_repls[strchr(esc_chars,*d) - esc_chars]) + 2;
	ch = d;
      };
    };
    // Check if escaping is needed
    if (need_len == (int)strlen(str_buf))
      // Escaping is not needed
      return str_buf;
    else {
      // Escaping is needed
      if (xml_buf)
	// Reset old string, because we are not appending to it
	*xml_buf = '\0';
      make_room (&xml_buf, &xml_buf_len, need_len + 1, (xml_buf != NULL));
      char* to = xml_buf;
      for (ch = str_buf; *ch; ch++) {
	d = strpbrk(ch, esc_chars);
	if (d == NULL) {
	  // append the rest of the string
	  strcpy(to, ch);
	  to += strlen(to);
	  break;
	} else {
	  if (d > ch) {
	    // append characters before escape
	    memcpy (to, ch, d - ch);
	    to += (d - ch);
	  };
	  // append escape-string
	  *to++ = '&';
	  strcpy(to, esc_repls[strchr(esc_chars,*d) - esc_chars]);
	  to += strlen(to);
	  *to++ = ';';
	  ch = d;
	};
      };
      *to = '\0';
      return xml_buf;
    };
  } else
    return "";
}


void c_fstring :: uppercase()
{
  for (char* c = str_buf; c && *c; c++)
    *c = toupper(*c);
}


void c_fstring :: trim()
{
  char* c;
  char* data = str_buf;

  if (!data)
    return;

  // Trim leading data
  for (c = data; *c && isspace(*c); c++);
  if (c > data)
    remove(0, c - data);
  if (strlen(data)) {
    c = data + strlen(data) - 1;
    while (c > data && isspace(*c)) c--;
    *(c + 1) = '\0';
  };
}


bool c_fstring :: equals (const char* with_value)
{
  return strcmp(as_string(), with_value) == 0;
}
