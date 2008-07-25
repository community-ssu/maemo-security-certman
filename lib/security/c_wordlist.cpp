// ------------------------------------------------------------------------
/// \file c_wordlist.cpp
/// \brief The implementation of the c_wordlist class
//
// Revision $Id: c_wordlist.cpp,v 1.6 2005/01/03 07:00:03 jum Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#include "c_wordlist.h"
#include "sec_common.h"

#include <string.h>
#include <ctype.h>


c_wordlist :: c_wordlist()
{
  ;
}


c_wordlist :: c_wordlist(const char* from_text, int len)
{
  parse(from_text, len);
}


c_wordlist :: ~c_wordlist()
{
}


void c_wordlist :: parse(const char* from_text, int len)
{
  char* start = (char*) from_text;
  char* c = start;
  int istat = 0;

  if (len == 0)
    len = strlen(from_text);

  while (*c && len) {
    if (isspace(*c)) {
      if (istat) {
	words.add_value(new c_fstring(start, c - start));
	istat = 0;
      };
    } else {
      if (istat == 0) {
	// First non-space character
	start = c;
	istat = 1;
      };
    };
    len--;
    c++;
  };
  if (c > start)
    words.add_value(new c_fstring(start, c - start));
}

void c_wordlist :: add(const char* word)
{
  words.add_value(new c_fstring(word));
}


bool c_wordlist :: contains (const char* word)
{
  for (int i = 0; i < nbrof_words(); i++) {
    if (strcmp(word, words.value(i)->as_string()) == 0)
      return true;
  };
  return false;
}


int c_wordlist :: nbrof_words()
{
  return words.nbrof_values();
}


const char* c_wordlist :: word(int pos)
{
  c_fstring* res = words.value(pos);
  if (!res) {
    ERROR("wordlist index %d out-of-bounds", pos);
  };
  return res->as_string();
}


const char* c_wordlist :: as_string()
{
  str_buf.reset();
  for (int i = 0; i < nbrof_words(); i++) {
    str_buf.append(word(i));
    if (i + 1 < nbrof_words())
      str_buf.append(",");
  };
  return str_buf.as_string();
}


void c_wordlist :: reset()
{
  words.reset();
}
