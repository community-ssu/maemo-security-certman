// ------------------------------------------------------------------------
/// \file c_map.cpp
/// \brief The implementation of the c_map class
//
// Revision $Id: c_map.cpp,v 1.5 2005/01/03 07:00:03 jum Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#include "c_map.h"
#include "sec_common.h"

#include <string.h>
#include <stdio.h>

c_map :: c_map(bool case_sensitive)
{
  use_strcmpi = !case_sensitive;
}


c_map :: ~c_map()
{
}


void c_map :: map(const char* key, const char* value, bool override)
{
  int pos = key_pos(key);

  if (pos == -1) {
    c_fstring* fkey = new c_fstring(key);
    if (use_strcmpi)
      fkey->uppercase();
    keys.add_value(fkey);
    vals.add_value(new c_fstring(value));

  } else if (override) {
    c_fstring* valptr = vals.value(pos);
    valptr->reset();
    valptr->append(value);
  };
}


void c_map :: map(const char* key, const char* value)
{
  // The default is to override
  map(key, value, true);
}


void c_map :: map(const char* key, long value)
{
  char help [20];

  sprintf (help, "%ld", value);
  map (key, help, true);
}


void c_map :: map(const char* key, const char* value, int bytes)
{
  c_fstring temp;

  temp.append(value, bytes);
  map (key, temp.as_string(), true);
}


// Just sequential search at the moment. If maps grow large, implement binary
// search
int c_map :: key_pos (const char* of_key)
{
  c_fstring loc_key(of_key);

  if (use_strcmpi)
    loc_key.uppercase();
    
  for (int i = 0; i < keys.nbrof_values(); i++) {
    if (keys.value(i)->equals(loc_key.as_string()))
	return i;
  };
  return -1;
}


void c_map :: unmap(const char* key)
{
  int pos = key_pos(key);
  if (pos >= 0) {
    keys.remove_value(pos);
    vals.remove_value(pos);
  };
}


bool c_map :: contains(const char* key)
{
  return key_pos(key) >= 0;
}


const char* c_map :: value(const char* key, bool required, const char* defval)
{
  int pos = key_pos(key);

  if (pos >= 0)
    return vals.value(pos)->as_string();
  else if (required) {
    ERROR("required key '%s' not found from map", key);
  };
  return defval;
}


int c_map :: nbrof_values ()
{
  return keys.nbrof_values();
}


const char* c_map :: key_value (int of_pos)
{
  if (of_pos >= 0 && of_pos < nbrof_values())
    return keys.value(of_pos)->as_string();
  else
    return "";
}


const char* c_map :: mapped_value (int of_pos)
{
  if (of_pos >= 0 && of_pos < nbrof_values())
    return vals.value(of_pos)->as_string();
  else
    return "";
}


bool c_map :: equals (char* value_mapped_to_key, char* with_string, bool case_sensitive)
{
  int pos = key_pos(value_mapped_to_key);
  if (pos < 0)
    return false;
  if (!case_sensitive) {
    c_fstring left(vals.value(pos)->as_string());
    c_fstring right(with_string);
    left.uppercase();
    right.uppercase();
    return (strcmp(left.as_string(), right.as_string()) == 0);
  } else {
    return (strcmp(vals.value(pos)->as_string(), with_string) == 0);
  };
}


void c_map :: reset ()
{
  keys.reset();
  vals.reset();
}
