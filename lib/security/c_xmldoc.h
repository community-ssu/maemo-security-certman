/* -*- mode:c; tab-width:4; c-basic-offset:4;
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

/// \file c_xmldoc.h
/// \brief The c_xmldoc class

#ifndef C_XMLDOC_DEF
#define C_XMLDOC_DEF

#include "c_xmlnode.h"
#include <expat.h>
#include <string>



/// \class c_xmldoc
/// \brief XML DOM implementation
///
/// The c_xmldoc class provides an easy to use interface for handling
/// relatively small xml documents, that fit easily into memory.
/// It is handy for parameter and data file handling and constructing
/// or parsing XML-format messages.

class c_xmldoc
{
public:
	/// \brief Constructor
	c_xmldoc ();

	/// \brief Destructor
	~c_xmldoc ();

	/// \brief Parse xml from a file
	/// \param file_name The name of the file

	void parse_file (const char* file_name);

	/// \brief Parse xml from a string
	/// \param xml_as_string The text of the xml
	/// \param length The length of the given string. If zero, 
	/// strlen(xml_as_string) is assumed

	void parse_string (const char* xml_as_string, int length);

	/// \brief Release the parser. Use this method to release 
	/// the resources reserved by the expat parser, 
	/// if it probably is not needed any more.
	///
	/// It is safe to make this call and continue parsing,
	/// since the parser is re-initialized automatically

	void release_parser();

	/// \brief Release the string buffer allocated for 
	/// converting the DOM-tree into a string
	/// Use this function to minimize runtime memory usage. 
	/// It is not mandatory to call this function, since 
	/// the destructor will release the buffer eventually anyway

	void release_string_buffer ();

	/// \brief Create a new xml document with the given node as root
	/// \param root_node_name The name of the root tag
	/// \returns a pointer to the root node
	
	c_xmlnode* create (const char* root_node_name);
	
	/// \brief Return the current root node
	/// \returns A pointer to the root node, or NULL, 
	/// if the document is empty

	c_xmlnode* root();

	/// \brief Return the contents of the document
	/// \param pretty_printing if true, add newlines and
	/// indentation
	/// returns A string that contains the whole document
	string as_string (bool pretty_printing);

	/// \brief Release the whole DOM-tree

	void release_content(void);

	/// \brief Save the contents of the document into a file
	/// \param to_file The name of the file where 
	/// the contents are written to
	
	void save(const char* to_file);


	// Expat-parser's hook routines
	// ----------------------------
	// These need to be visible in order to be called from the
	// actual, static hook routines
	
	/// \brief Receive an element start from the expat-parser
	/// \param element_name the name of the element
	/// \param attributes possible attributes, as a NULL-terminated
	/// string list of name=value pairs
	
	void xml_element_start(const char* element_name, const char** attributes);

	/// \brief Receive an element end from the expat-parser
	/// \param element_name the name of the element

	void xml_element_end(const char* element_name);

	/// \brief Receive a piece of node content data
	/// \param data The data
	/// \param len The length of data

	void xml_character_data(const char* data, const int len);
	
	/// \brief Indicate that what follows is CDATA

	void xml_cdata_start();

	/// \brief CDATA ends

	void xml_cdata_end();

	/// \var trim_whitespace
	/// \brief Set this trigger to make the parser to discard leading
	/// and trailing whitespace from XML content data

	bool trim_whitespace;

private:
	void init_parser();
	void xml_parsing_error();

	XML_Parser expat_parser;
	c_xmlnode* root_node;
	c_xmlnode* cur_node;
	char* xml_str_buf;
};
#endif
