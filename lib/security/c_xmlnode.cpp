/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
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
#include "sec_common.h"

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>


c_xmlnode :: c_xmlnode (c_xmlnode* of_parent, const char* of_name)
{
	parent_ptr = of_parent;
	is_cdata = false;

	if (!of_name || strlen(of_name) == 0) {
		ERROR("no name given for a node");
		return;
	}
	elem_name = of_name;
}


c_xmlnode :: ~c_xmlnode ()
{
	reset();
	elem_name = "";
}


const char* c_xmlnode :: name ()
{
	return(elem_name.c_str());
}


c_xmlnode* c_xmlnode :: parent()
{
	return(parent_ptr);
}


void c_xmlnode :: append_content (const char* data, int len)
{
	if (!data || !strlen(data))
		return;
	if (is_cdata && cdata_ended)
		return;
	content_str.append(data, len);
}


void c_xmlnode :: append_content (const char* data)
{
	if (data)
		append_content(data, strlen(data));
}


void c_xmlnode :: append_file (const char* file_name)
{
	ERROR("not implemented");
#if 0
	string cont;
	cont.append_file(file_name);
	append_content(cont.as_string());
#endif
}


const char* c_xmlnode :: content ()
{
	return content_str.c_str();
}


void c_xmlnode :: reset_content ()
{
	content_str = "";
}


void c_xmlnode :: append_attribute (const char* name, const char* value)
{
	attributes[name] = value;
}


void c_xmlnode :: append_attribute (const char* name, long value)
{
	char as_str[20];

	sprintf(as_str, "%ld", value);
	append_attribute(name, as_str);
}


int c_xmlnode :: nbrof_attributes ()
{
	return attributes.size();
}


const char* c_xmlnode :: attribute_name (int of_pos)
{
	// TODO: is there a more efficient method of doing this?
	map<string, string>::const_iterator ii = attributes.begin();

	if (of_pos < 0 || of_pos >= attributes.size())
		ERROR("index %d out of range", of_pos);

	while (of_pos > 0 && ii != attributes.end()) {
		ii++;
		of_pos--;
	}
	return(ii->first.c_str());
}


const char* c_xmlnode :: attribute_value (int of_pos)
{
	// TODO: is there a more efficient method of doing this?
	map<string, string>::const_iterator ii = attributes.begin();

	if (of_pos < 0 || of_pos >= attributes.size())
		ERROR("index %d out of range", of_pos);

	while (of_pos > 0 && ii != attributes.end()) {
		ii++;
		of_pos--;
	}
	return(ii->second.c_str());
}


void c_xmlnode :: remove_attribute (const char* name)
{
	map<string, string>::iterator ii = attributes.find(name);

	if (ii != attributes.end()) 
		attributes.erase(ii);
	else {
		ERROR("no such element '%s'", name);
	}
}


const char* c_xmlnode :: attribute (const char* name, bool required, const char* defval)
{
	map<string, string>::const_iterator ii = attributes.find(name);

	if (ii != attributes.end())
		return(ii->second.c_str());
	else if (!required)
		return(defval);
	else {
		ERROR("required attribute '%s' not found", name);
		return("");
	}
}


c_xmlnode* c_xmlnode :: append_child (const char* element_name)
{
	c_xmlnode* ret_val = new c_xmlnode(this, element_name);
	children.push_back(ret_val);
	return(ret_val);
}


int c_xmlnode :: nbrof_children ()
{
	return(children.size());
}


c_xmlnode* c_xmlnode :: child (int of_pos)
{
	if (of_pos < 0 || of_pos >= children.size()) {
		ERROR("index %d out of range", of_pos);
		return(NULL);
	}
	return children[of_pos];
}


c_xmlnode* c_xmlnode :: child(const char* of_name, bool required)
{
	for (unsigned i = 0; i < children.size(); i++) {
		if (strcmp(children[i]->name(),of_name) == 0)
			return(children[i]);
	}
	if (required) {
		ERROR("required child '%s' of '%s' not found", of_name, xpath().c_str());
	}
	return NULL;
}


void c_xmlnode :: remove_child (int of_pos)
{
	if (of_pos < 0 || of_pos >= children.size()) {
		ERROR("index %d out of range", of_pos);
		return;
	}
	delete(children[of_pos]);
	// TODO: is this necessary?
	children[of_pos] = NULL;
	vector<c_xmlnode*>::iterator ipos;
	for (; of_pos; ipos++, of_pos--);
	children.erase(ipos);
}


void c_xmlnode :: set_cdata (bool to_this)
{
	if (to_this) {
		is_cdata = to_this;
		cdata_ended = false;
		content_str = "";
	} else
		cdata_ended = true;
}


string c_xmlnode :: as_string (bool add_linebreaks, int indent_width, int indent_level)
{
	unsigned i;
	string result;
	map<string, string>::const_iterator ii;

	if (add_linebreaks)
		result.append(indent_width * indent_level, ' ');

	result.append("<");
	result.append(elem_name);

	for (ii = attributes.begin(); ii != attributes.end(); ii++) {
		result.append(" ");
		result.append(ii->first);
		result.append("=\"");
		// TODO: should be XML escaped
		result.append(ii->second);
		result.append("\"");
	}

	if (children.size() > 0) {
		// Compound node
		result.append(">");
		if (add_linebreaks)
			result.append("\n");

		for (i = 0; i < children.size(); i++) {
			result.append(children[i]->as_string(add_linebreaks, 
												 indent_width, 
												 indent_level + 1));
		}

		// End tag on its own line
		if (add_linebreaks)
			result.append(indent_width * indent_level, ' ');
		result.append("</");
		result.append(elem_name);
		result.append(">");

  } else {

		// Simple node, everything at the same line
#if 0
		if (is_cdata) {
			temp_buf->append(strlen(content_str.as_string()) + 20,
							 "><![CDATA[%s]]>", content_str.as_string());
			if (add_linebreaks) {
				result.append("\n");
				result.append(indent_width * indent_level, ' ');
			}
			result.append("</");
			result.append(elem_name);
			result.append(">");
		} else 
#endif
		if (content_str != "") {
    		result.append(">");
			result.append(content_str);
			result.append("</");
			// TODO: should be XML escaped
			result.append(elem_name);
			result.append(">");
    	} else {
			// Empty string is taken for a null value
			result.append("/>");
		}
	}
	if (add_linebreaks)
		result.append("\n");

	return(result);
}


void c_xmlnode :: trim_whitespace()
{
	DEBUG(0, "not implemented");
#if 0
	content_str.trim();
#endif
}


c_xmlnode* c_xmlnode :: navigate(const char* to_xpath, bool required)
{
	const char* xp = to_xpath;
	const char* start;
	c_xmlnode* result = this;

	if (!xp || strlen(xp) == 0) {
		return(this);
	}

	if (*xp == '/') {
		/*
		 * Go to root node
		 */
		for (; result->parent_ptr; result = result->parent_ptr);
		xp++;
	}
	for (start = xp; *xp; xp++) {
		if (*xp == '/') {
			string child_name(start, xp - start);
			if (xp != start) {
				start = xp + 1;
				if (child_name == "..")
					result = result->parent_ptr;
				else if (child_name != ".")
					result = result->child(child_name.c_str(), required);
			} else {
				ERROR("empty path element in '%s'", to_xpath);
			}
			if (!result && required) {
				ERROR("required path element '%s' not found", 
					  child_name.c_str());
			}
		}
	}
	return(result);
}


string c_xmlnode :: xpath()
{
	c_xmlnode* node = this;
	string result;

	while (node) {
		result.insert(0, node->elem_name);
		result.insert(0, "/");
		node = node->parent_ptr;
	}
	return(result);
}


void c_xmlnode :: reset()
{
	DEBUG(0, "not implemented");
}
