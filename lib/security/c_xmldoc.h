/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
// ------------------------------------------------------------------------
/// \file c_xmldoc.h
/// \brief The c_xmldoc class
//
// Revision $Id: c_xmldoc.h,v 1.5 2005/01/03 07:14:16 jum Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#ifndef C_XMLDOC_DEF
#define C_XMLDOC_DEF

#include "c_xmlnode.h"
#include <expat.h>
#include <string>

/// \class c_xmldoc
/// \ingroup highleveltools
/// \brief XML DOM implementation
///
/// The c_xmldoc class provides an easy to use interface for handling
/// relatively small xml documents, that fit easily into central memory.
/// It is used for parameter and data file handling and constructing
/// and parsing the messages exchanged with the Service Manager

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

	/// \brief Return the contents of the document as text
	/// \param pretty_printing when false, the DOM tree is returned as 
	/// a continuous string without line breaks or indentation, 
	/// which is a suitable format for automatic parsing;
	/// when true, the output is nicely indented.
	/// \returns a pointer to a buffer containing the xml as text.

	const char* as_string (bool pretty_printing);

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

	/// \brief Return the absolute file name where the XML data was read, 
	/// or an empty string, if the data was not read from a file
	/// \returns The full name of the original XML-file

	const char* xml_file_path();

	/// \brief Navigate into the given node, if one exist
	/// \param xpath A simplified xpath-expression of format 
	/// "/node1/node2/../node3"
	/// If the expression starts with "/", the navigation starts from 
	/// the root node, otherwise it is relative to the current position 
	/// (the node returned by the preceding navigate-call). 
	/// String ".." refers to the parent, children are identified 
	/// by unique names. If multiple children  at the same level 
	/// have the same name, the first possible path is followed.
	/// \param required If true, and no given node is found, an exception 
	/// is thrown
	/// \returns A pointer to the requested node or NULL, 
	/// if no matching node is found and the required-parameter was false

	c_xmlnode* navigate(const char* xpath, bool required);

	/// \brief Release the whole DOM-tree

	void reset_content ();

	/// \brief Save the contents of the document into a file
	/// \param to_file The name of the file where 
	/// the contents are written to
	
	void save(const char* to_file);

	/// \brief Save the contents of the document into 
	/// the file where the data was initially read from or last
	/// saved to

	void save();

	// Expat-parser's hook routines
	// ----------------------------
	
	/// \brief Receive an element start from the expat-parser
	/// \param element_name the name of the element
	/// \param attributes possible attributes, as a NULL-terminated
	/// string list of name=value pairs
	
	void xml_element_start(char* element_name, char** attributes);

	/// \brief Receive an element end from the expat-parser
	/// \param element_name the name of the element

	void xml_element_end(char* element_name);

	/// \brief Receive a piece of node content data
	/// \param data The data
	/// \param len The length of data

	void xml_character_data(char* data, int len);
	
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
	string file_path;
};
#endif
