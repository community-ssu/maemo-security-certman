/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*-
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

// ------------------------------------------------------------------------
/// \file c_xmlnode.cpp
/// \brief The implementation of the c_xmlnode class

#include "c_xmlnode.h"
#include "c_xmldoc.h"
#include "maemosec_common.h"

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>


c_xmlnode::c_xmlnode(c_xmlnode* of_parent, const char* of_name)
{
	if (!of_name || strlen(of_name) == 0) {
		MAEMOSEC_ERROR("XML tag must have a name");
		return;
	}
	m_parent = of_parent;
	is_cdata = false;
	m_tagname = of_name;
}


c_xmlnode::~c_xmlnode()
{
	m_tagname = "";
	for (unsigned i = 0; i < m_children.size(); i++)
		delete(m_children[i]);
}


const char* c_xmlnode :: name ()
{
	return(m_tagname.c_str());
}


c_xmlnode* c_xmlnode :: parent()
{
	return(m_parent);
}


void c_xmlnode :: append_content (const char* data, int len)
{
	if (!data || !strlen(data))
		return;
	if (is_cdata && cdata_ended)
		return;
	m_content.append(data, len);
}


void c_xmlnode :: append_content (const char* data)
{
	if (data)
		append_content(data, strlen(data));
}


void c_xmlnode :: append_file (const char* file_name)
{
	MAEMOSEC_ERROR("not implemented");
#if 0
	string cont;
	cont.append_file(file_name);
	append_content(cont.as_string());
#endif
}


const char* c_xmlnode :: content ()
{
	return m_content.c_str();
}


void c_xmlnode :: append_attribute (const char* name, const char* value)
{
	m_attributes[name] = value;
}


void c_xmlnode :: append_attribute (const char* name, long value)
{
	char as_str[20];

	sprintf(as_str, "%ld", value);
	append_attribute(name, as_str);
}


int c_xmlnode :: nbrof_attributes ()
{
	return m_attributes.size();
}


const char* c_xmlnode :: attribute_name (int of_pos)
{
	// TODO: is there a more efficient method of doing this?
	map<string, string>::const_iterator ii = m_attributes.begin();

	if (of_pos < 0 || of_pos >= m_attributes.size())
		MAEMOSEC_ERROR("index %d out of range", of_pos);

	while (of_pos > 0 && ii != m_attributes.end()) {
		ii++;
		of_pos--;
	}
	return(ii->first.c_str());
}


const char* c_xmlnode :: attribute_value (int of_pos)
{
	// TODO: is there a more efficient method of doing this?
	map<string, string>::const_iterator ii = m_attributes.begin();

	if (of_pos < 0 || of_pos >= m_attributes.size())
		MAEMOSEC_ERROR("index %d out of range", of_pos);

	while (of_pos > 0 && ii != m_attributes.end()) {
		ii++;
		of_pos--;
	}
	return(ii->second.c_str());
}


void c_xmlnode :: remove_attribute (const char* name)
{
	map<string, string>::iterator ii = m_attributes.find(name);

	if (ii != m_attributes.end()) 
		m_attributes.erase(ii);
	else {
		MAEMOSEC_ERROR("no such element '%s'", name);
	}
}


const char* c_xmlnode :: attribute (const char* name, bool required, const char* defval)
{
	map<string, string>::const_iterator ii = m_attributes.find(name);

	if (ii != m_attributes.end())
		return(ii->second.c_str());
	else if (!required)
		return(defval);
	else {
		MAEMOSEC_ERROR("required attribute '%s' not found", name);
		return("");
	}
}


c_xmlnode* c_xmlnode :: append_child (const char* element_name)
{
	c_xmlnode* ret_val = new c_xmlnode(this, element_name);
	m_children.push_back(ret_val);
	return(ret_val);
}


int c_xmlnode :: nbrof_children ()
{
	return(m_children.size());
}


c_xmlnode* c_xmlnode :: child (int of_pos)
{
	if (of_pos < 0 || of_pos >= m_children.size()) {
		MAEMOSEC_ERROR("index %d out of range", of_pos);
		return(NULL);
	}
	return m_children[of_pos];
}


c_xmlnode* c_xmlnode :: child(const char* of_name, bool required)
{
	for (unsigned i = 0; i < m_children.size(); i++) {
		if (strcmp(m_children[i]->name(),of_name) == 0)
			return(m_children[i]);
	}
	if (required) {
		MAEMOSEC_ERROR("required child '%s' of '%s' not found", of_name, xpath().c_str());
	}
	return NULL;
}


void c_xmlnode :: remove_child (int of_pos)
{
	if (of_pos < 0 || of_pos >= m_children.size()) {
		MAEMOSEC_ERROR("index %d out of range", of_pos);
		return;
	}
	delete(m_children[of_pos]);
	// TODO: is this necessary?
	m_children[of_pos] = NULL;
	vector<c_xmlnode*>::iterator ipos;
	for (; of_pos; ipos++, of_pos--);
	m_children.erase(ipos);
}


void c_xmlnode :: set_cdata (bool to_this)
{
	if (to_this) {
		is_cdata = to_this;
		cdata_ended = false;
		m_content = "";
	} else
		cdata_ended = true;
}


string 
c_xmlnode::as_string (bool add_linebreaks, int indent_width, int indent_level)
{
	unsigned i;
	string result;
	map<string, string>::const_iterator ii;

	if (add_linebreaks)
		result.append(indent_width * indent_level, ' ');

	result.append("<");
	result.append(m_tagname);

	for (ii = m_attributes.begin(); ii != m_attributes.end(); ii++) {
		result.append(" ");
		result.append(ii->first);
		result.append("=\"");
		// TODO: should be XML escaped
		result.append(ii->second);
		result.append("\"");
	}

	if (m_children.size() > 0) {
		// Compound node
		result.append(">");
		if (add_linebreaks)
			result.append("\n");

		for (i = 0; i < m_children.size(); i++) {
			result.append(m_children[i]->as_string(add_linebreaks, 
												   indent_width, 
												   indent_level + 1));
		}

		// End tag on its own line
		if (add_linebreaks)
			result.append(indent_width * indent_level, ' ');
		result.append("</");
		result.append(m_tagname);
		result.append(">");

  } else {
		if (is_cdata) {
			result.append("><![CDATA[");
			result.append(m_content);
			result.append("]]");
			if (add_linebreaks) {
				result.append("\n");
				result.append(indent_width * indent_level, ' ');
			}
			result.append("</");
			result.append(m_tagname);
			result.append(">");

		} else if (m_content != "") {
    		result.append(">");
			result.append(m_content);
			result.append("</");
			// TODO: should be XML escaped
			result.append(m_tagname);
			result.append(">");

    	} else {
			result.append("/>");
		}
	}
	if (add_linebreaks)
		result.append("\n");

	return(result);
}


void c_xmlnode :: trim_whitespace()
{
	MAEMOSEC_DEBUG(0, "not implemented");
#if 0
	m_content.trim();
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
		for (; result->m_parent; result = result->m_parent);
		xp++;
	}
	for (start = xp; *xp && (NULL != result); xp++) {
		if (*xp == '/') {
			string child_name(start, xp - start);
			if (xp != start) {
				start = xp + 1;
				if (child_name == "..")
					result = result->m_parent;
				else if (child_name != ".")
					result = result->child(child_name.c_str(), required);
			} else {
				MAEMOSEC_ERROR("empty path element in '%s'", to_xpath);
			}
			if (NULL == result && required) {
				MAEMOSEC_ERROR("required path element '%s' not found", 
							   child_name.c_str());
			}
		}
	}
	return(result);
}


string 
c_xmlnode::xpath()
{
	c_xmlnode* node = this;
	string result;

	while (node) {
		result.insert(0, node->m_tagname);
		result.insert(0, "/");
		node = node->m_parent;
	}
	return(result);
}
