// ------------------------------------------------------------------------
/// \file c_xmlnode.cpp
/// \brief The implementation of the c_xmlnode class
//
// Revision $Id: c_xmlnode.cpp,v 1.8 2006/01/10 16:36:40 a2vepsal Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#include "c_xmlnode.h"
#include "c_xmldoc.h"
#include "c_wordlist.h"
#include "sec_common.h"

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>


c_xmlnode :: c_xmlnode (c_xmldoc* of_doc, c_xmlnode* of_parent, const char* of_name)
  : attributes(true)
{
  doc_ptr = of_doc;
  parent_ptr = of_parent;
  is_cdata = false;

  if (!of_name || strlen(of_name) == 0) {
    // ERROR
    elem_name = NULL;
    return;
  };

  elem_name = (char*) malloc(strlen(of_name) + 1);
  strcpy (elem_name, of_name);
}


c_xmlnode :: ~c_xmlnode ()
{
  reset();
  if (elem_name)
    free ((void*)elem_name);
}


const char* c_xmlnode :: name ()
{
  if (elem_name)
    return elem_name;
  else
    return "";
}


c_xmldoc* c_xmlnode :: doc()
{
  return doc_ptr;
}


c_xmlnode* c_xmlnode :: parent()
{
  return parent_ptr;
}


void c_xmlnode :: append_content (const char* data, int len)
{
  if (!data || !strlen(data))
    return;
  if (is_cdata && cdata_ended)
    return;
  content_str.append (data, len);
}


void c_xmlnode :: append_content (const char* data)
{
  if (data)
    append_content(data, strlen(data));
}


void c_xmlnode :: append_file (const char* file_name)
{
  c_fstring cont;

  cont.append_file(file_name);
  append_content(cont.as_string());
}


const char* c_xmlnode :: content ()
{
  return content_str.as_string();
}


void c_xmlnode :: reset_content ()
{
  content_str.reset();
}


void c_xmlnode :: append_attribute (const char* name, const char* value)
{
  attributes.map(name, value);
}


void c_xmlnode :: append_attribute (const char* name, long value)
{
  char as_str[20];

  sprintf(as_str, "%ld", value);
  append_attribute(name, as_str);
}


int c_xmlnode :: nbrof_attributes ()
{
  return attributes.nbrof_values();
}


const char* c_xmlnode :: attribute_name (int of_pos)
{
  return attributes.key_value(of_pos);
}


const char* c_xmlnode :: attribute_value (int of_pos)
{
  return attributes.mapped_value(of_pos);
}


void c_xmlnode :: remove_attribute (const char* name)
{
  attributes.unmap(name);
}


const char* c_xmlnode :: attribute (const char* name, bool required, const char* defval)
{
  return attributes.value(name, required, defval);
}


c_xmlnode* c_xmlnode :: append_child (const char* element_name)
{
  c_xmlnode* ret_val = new c_xmlnode(doc_ptr, this, element_name);
  children.add_value(ret_val);
  return ret_val;
}


int c_xmlnode :: nbrof_children ()
{
  return children.nbrof_values();
}


c_xmlnode* c_xmlnode :: child (int of_pos)
{
  return children.value(of_pos);
}


c_xmlnode* c_xmlnode :: child(char* of_name, bool required)
{
  for (int i = 0; i < children.nbrof_values(); i++)
    if (strcmp(children.value(i)->name(), of_name) == 0)
      return child(i);
  if (required) {
    ERROR("required child '%s' of '%s' not found", of_name, xpath());
  };
  return NULL;
}


void c_xmlnode :: remove_child (int of_pos)
{
  children.remove_value(of_pos);
}


void c_xmlnode :: set_cdata (bool to_this)
{
  if (to_this) {
    is_cdata = to_this;
    cdata_ended = false;
    content_str.reset();
  } else
    cdata_ended = true;
}


c_fstring* c_xmlnode :: as_fstring (bool add_linebreaks, int indent_width, int indent_level)
{
  c_fstring* temp_buf = new c_fstring();
  c_fstring* child_buf = NULL;
  c_fstring f_avalue;
  int i;

  if (add_linebreaks)
    temp_buf->append(' ', indent_width * indent_level);

  // Open tag
  temp_buf->append(strlen(elem_name) + 1, "<%s", elem_name);

  for (i = 0; i < attributes.nbrof_values(); i++) {
    const char* aname = attribute_name(i);
    f_avalue.append(attribute_value(i));
    const char* avalue = f_avalue.as_xml_string();
    temp_buf->append(strlen(aname) + strlen(avalue) + 6, " %s=\"%s\"", aname, avalue);
    f_avalue.reset();
  };

  if (children.nbrof_values() > 0) {
    // Compound node
    temp_buf->append(">");
    if (add_linebreaks)
      temp_buf->append("\n");

    for (i = 0; i < children.nbrof_values(); i++) {
      child_buf = children.value(i)->as_fstring(add_linebreaks, indent_width, indent_level + 1);
      temp_buf->append(child_buf->as_string());
      delete(child_buf);
    };

    // End tag on its own line
    if (add_linebreaks)
      temp_buf->append(' ', indent_width * indent_level);
    temp_buf->append(strlen(elem_name) + 3, "</%s>", elem_name);

  } else {
    // Simple node, everything at the same line
    if (is_cdata) {
      temp_buf->append(strlen(content_str.as_string()) + 20,
		       "><![CDATA[%s]]>", content_str.as_string());
      if (add_linebreaks) {
	temp_buf->append("\n");
	temp_buf->append(' ', indent_width * indent_level);
      };
      temp_buf->append(strlen(elem_name) + 3, "</%s>", elem_name);
    } else if (strlen(content_str.as_string())) {
    	const char* avalue = NULL;
    	if (strcmp(elem_name,"Command") == 0) {
    		avalue = content_str.as_string();
    		temp_buf->append(strlen(avalue) + strlen(elem_name) + 4, " %s</%s>", avalue, elem_name);
    	} else {
    		avalue = content_str.as_xml_string();
    		temp_buf->append(strlen(avalue) + strlen(elem_name) + 4, ">%s</%s>", avalue, elem_name);
    	}
    } else {
      // Empty string is taken for a null value
      temp_buf->append("/>");
    };
  };
  if (add_linebreaks)
    temp_buf->append("\n");

  return temp_buf;
}


void c_xmlnode :: trim_whitespace()
{
  content_str.trim();
}


c_xmlnode* c_xmlnode :: navigate(const char* to_xpath, bool required)
{
  char* sep;
  char s_xpath [255];
  char *l_xpath;
  char* xp;
  c_xmlnode* node;

  if (strlen(to_xpath) < sizeof(s_xpath)) {
    strcpy (s_xpath, to_xpath);
    l_xpath = s_xpath;
  } else 
    l_xpath = (char*) malloc(strlen(to_xpath) + 1);

  xp = l_xpath;
  if (*xp == '/') {
    node = doc_ptr->root();
    xp++;
  } else
    node = this;

  while (*xp) {
    sep = strchr(xp, '/');
    if (sep)
      *sep = '\0';

    if (strlen(xp) == 0) {
      if (l_xpath != s_xpath)
	free(l_xpath);
      ERROR("invalid xpath-expression '%s'", to_xpath);
    };
      
    if (strcmp(xp, "..") == 0)
      node = node->parent();

    else if (strcmp(xp, ".") == 0) 
      // We are already there
      ;

    else {
      c_xmlnode* child_ptr = NULL;
      for (int i = 0; i < node-> nbrof_children(); i++) {
	child_ptr = (c_xmlnode*) node->child(i);
	if (strcmp(child_ptr->name(), xp) == 0) 
	  break;
	else
	  child_ptr = NULL;
      };
      node = child_ptr;
    };

    if (node == NULL) {
      // Navigation lead as nowhere
      if (required) {
	if (l_xpath != s_xpath)
	  free(l_xpath);
	ERROR("required xpath '%s' not found from '%s'",
		     to_xpath, xpath());
      } else
	return NULL;
    };

    if (sep)
      xp = sep + 1;
    else
      break;
  };

  if (l_xpath != s_xpath)
    free(l_xpath);

  return node;
}


const char* c_xmlnode :: xpath()
{
  c_wordlist xpath_rev;

  xpath_buf.reset();
  for (c_xmlnode* traverse = this; traverse; traverse = traverse->parent_ptr)
    xpath_rev.add(traverse->elem_name);
  xpath_buf.append("/");
  for (int i = xpath_rev.nbrof_words(); i > 0; i--) 
    xpath_buf.append(255, "%s/", xpath_rev.word(i - 1));

  return xpath_buf.as_string();
}


void c_xmlnode :: reset()
{
  content_str.reset();
  xpath_buf.reset();
  attributes.reset();
  children.reset();
}
