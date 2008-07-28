/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
// ------------------------------------------------------------------------
/// \file c_xmlnode.h
/// \brief The c_xmlnode class
//
// Revision $Id: c_xmlnode.h,v 1.8 2005/01/03 07:14:16 jum Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#ifndef C_XMLNODE_DEF
#define C_XMLNODE_DEF

// STL headers
#include <string>
#include <vector>
#include <map>
using namespace std;

/// \class c_xmlnode
/// \ingroup highleveltools
/// \brief XML DOM implementation
///
/// This class is used together with the c_xmldoc-class to manage
/// XML as in-memory DOM-tree

class c_xmlnode 
{
public:
	/// \brief Constructor
	/// \param of_parent The node's parent (NULL, if this is root node)
	/// \param of_name The name of the element to create

	c_xmlnode (c_xmlnode* of_parent, const char* of_name);

	/// \brief Destructor
	~c_xmlnode ();

	/// \brief Return the parent of the node
	/// \return The c_xmlnode-pointer that was given in
	// the constructor

	c_xmlnode* parent();

	/// \brief Return the element's name
	/// \return The name of the element

	const char* name ();

	/// \brief Return the contents of a subtree as a string
	/// \param add_linebreaks Is the string pretty-printed or not
	/// \param indent_width With how many spaces to indent
	/// \param indent_level At what level to start the indentation
	/// \return a string containing the node as XML-text
	/// 
	/// Note! The returned c_fstring instance is dynamically allocated,
	/// and it is the caller's responsibility to delete 
	/// it when no longer needed

	string  as_string (bool add_linebreaks, 
					   int indent_width, 
					   int indent_level);
	
	/// \brief Append text into the content
	/// \param data The text to be appended
	/// \param len How many bytes of data

	void append_content (const char* data, int len);

	/// \brief Append text into the content
	/// \param data A NULL-terminated string

	void append_content (const char* data);

	/// \brief Append content from an external file
	/// \param file_name The name of the file where the
	/// data is read

	void append_file (const char* file_name);

	/// \brief Release the content

	void reset_content ();

	/// \brief Return the content
	/// \return A pointer to the (raw) content
	///
	/// When using this function, the data is in raw-format,
	/// i.e. no special characters are escaped. Use the as_fstring
	/// function to get the data as escaped.

	const char* content ();

	/// \brief Add an attribute to the node
	/// \param name The name of the attribute
	/// \param value The value of the attribute as a NULL-terminated
	/// string
	///
	/// If the node already contains an attribute with the same name,
	/// its current value is overwritten

	void append_attribute (const char* name, const char* value);

	/// \brief Add an attribute to the node
	/// \param name The name of the attribute
	/// \param value A numeric integer value of the attribute
	///
	/// If the node already contains an attribute with the same name,
	/// its current value is overwritten
	
	void append_attribute (const char* name, long value);

	/// \brief How many attributes the node contains
	/// \return The number of attributes

	int nbrof_attributes ();

	/// \brief Return the name of the nth attribute
	/// \param of_pos attribute order number, starting from 0
	/// \return The attribute name

	const char* attribute_name (int of_pos);

	/// \brief Return the value of the nth attribute
	/// \param of_pos attribute order number, starting from 0
	/// \return The attribute (raw) value

	const char* attribute_value (int of_pos);

	/// \brief Return an attribute value identified by its name
	/// \param name The name of the attribute
	/// \param required If true and the attribute does not exist,
	/// an exception is thrown
	/// \param defval If not required and the attribute does not
	/// exist, this value is returned

	const char* attribute(const char* name, 
						  bool required, 
						  const char* defval);

	/// \brief Remove an attribute
	/// \param name The name of the attribute
	///
	/// That's OK if the node does not contain the given attribute

	void remove_attribute (const char* name);

	/// \brief Return the selected subnode
	/// \param to_xpath An xpath-like expression, see c_xmldoc::navigate
	/// for further details
	/// \param required If the path is not found and this is set,
	/// an exceptions is thrown, otherwise NULL is returned

	c_xmlnode* navigate(const char* to_xpath, bool required);

	/// \brief Add a child-element to the node
	/// \param element_name The name of the child-element to add
	/// \return A pointer to the newly added element
	///
	/// The new child is always appended as the last element
	/// regardless whether the node already contains a 
	/// child-element with the same name or not
  
	c_xmlnode* append_child (const char* element_name);

	/// \brief How many child-elements the node has
	/// \return The number of child-elements

	int nbrof_children ();

	/// \brief Return a specific child element
	/// \param of_pos The order number of the child, starting from 0
	/// \return A pointer to the child-element or NULL of the given
	/// position is out-of-bounds

	c_xmlnode* child (int of_pos);

	/// \brief Return a child element specified by its name
	/// \param of_name The name of the child element
	/// \param required If true and there is no child element
	/// with the given name, an exception is thrown, otherwise
	/// NULL is returned
	///
	/// If the node contains several child elements with the
	/// given name, the first one is returned

	c_xmlnode* child (const char* of_name, bool required);

	/// \brief Remove a child element
	/// \param of_pos The order number of the child, starting from 0

	void remove_child (int of_pos);

	/// \brief Tag the content as CDATA
	/// \param to_this if true, the content is tagged as CDATA
	///
	/// In a CDATA-node the input data is not parsed for XML-escape
	/// sequences and when requesting an XML-string, the content
	/// is enclosed in a <![CDATA[...]]>-section
	
	void set_cdata(bool to_this);

	/// \brief Remove leading and trailing whitespace from the content
  
	void trim_whitespace();

	/// \brief Return the xpath of the node starting from root
	/// \return A string that contains the names of the parent
	/// nodes separated by '/'

	string xpath();

	/// \brief Release the node's contents and all subnodes
	
	void reset();

private:
	c_xmlnode* parent_ptr;

	string elem_name;

	string content_str;
	map<string,string> attributes;
	vector<c_xmlnode*> children;

	string xpath_buf;

	bool is_cdata;
	bool cdata_ended;
};
#endif
