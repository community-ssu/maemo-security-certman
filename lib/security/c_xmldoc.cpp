/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
// ------------------------------------------------------------------------
/// \file c_xmldoc.cpp
/// \brief The implementation of the c_xmldoc class

#include "c_xmldoc.h"
#include "sec_common.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/// \brief XML handlers. The instance pointer to xmldoc is passed in 
/// the user_data argument 

static void XMLCALL 
_exp_element_start (void* user_data, 
					const XML_Char* el, 
					const XML_Char** attr)
{
	c_xmldoc* to_doc = (c_xmldoc*) user_data;

	if (to_doc) {
		// Quick&dirty: cast XML_Char directly to char
		to_doc->xml_element_start((const char*)el, (const char**)attr);
		return;
	}
	// DEBUG
	DEBUG(2, "Element start %s\n", el);
	for (int i = 0; attr[i]; i += 2) 
		DEBUG(2, "  Attribute %s=%s\n", attr[i], attr[i + 1]);
}


static void XMLCALL 
_exp_element_end (void* user_data, 
				  const XML_Char* el)
{
	c_xmldoc* to_doc = (c_xmldoc*) user_data;

	if (to_doc) {
		// Quick&dirty: cast XML_Char directly to char
		to_doc->xml_element_end ((char*) el);
		return;
	}
	// DEBUG
	DEBUG(2, "Element end %s\n", el);
}

static void XMLCALL 
_exp_character_data (void* user_data, 
					 const XML_Char* data, 
					 int len)
{
	c_xmldoc* to_doc = (c_xmldoc*) user_data;

	if (to_doc) {
		// Quick&dirty: cast XML_Char directly to char
		to_doc->xml_character_data ((char*) data, len);
		return;
	}

	if (data && len) {
		string tmp(data, len);
		DEBUG (2, "  Content '%s'", tmp.c_str());
	}
}


static void XMLCALL 
_exp_start_cdata (void* user_data)
{
	c_xmldoc* to_doc = (c_xmldoc*) user_data;
	to_doc->xml_cdata_start();
}


static void XMLCALL 
_exp_end_cdata (void* user_data)
{
	c_xmldoc* to_doc = (c_xmldoc*) user_data;
	to_doc->xml_cdata_end();
}


// Class members
// -------------

c_xmldoc::c_xmldoc()
{
	root_node = NULL;
	cur_node = NULL;
	expat_parser = NULL;
	trim_whitespace = false;
}


void 
c_xmldoc::init_parser()
{
	if (expat_parser == NULL) {
		expat_parser = XML_ParserCreate(NULL);
		XML_SetStartElementHandler(expat_parser, _exp_element_start);
		XML_SetEndElementHandler(expat_parser, _exp_element_end);
		XML_SetCharacterDataHandler(expat_parser, _exp_character_data);
		XML_SetCdataSectionHandler(expat_parser, _exp_start_cdata, _exp_end_cdata);
		XML_SetUserData (expat_parser, (void*) this);
	}
}


void 
c_xmldoc::release_parser()
{
	if (expat_parser) {
		XML_ParserFree(expat_parser);
		expat_parser = NULL;
	}
}


void 
c_xmldoc::xml_parsing_error()
{
#if 0
	string errordesc;
	XML_Error rc = XML_GetErrorCode(expat_parser);
	int i, offset, size, prefix = 0;
	const char* input_context;
	const char* estring = XML_ErrorString(rc);

	errordesc.append(255, 
					 "XML error %d at line %d\n", 
					 rc, 
					 XML_GetCurrentLineNumber(expat_parser));

	input_context = XML_GetInputContext(expat_parser, &offset, &size);

	// Find the last newline before the error
	for (i = 0; i < offset; i++) {
		if (input_context[i] == '\n')
			prefix = i + 1;
	}

	// Truncate to the next newline after error
	for (i = offset; i < size; i++) {
		if (input_context[i] == '\n')
			size = i;
	}

	// Add context
	errordesc.append(1 + size, "%s\n", input_context);
	for (i = prefix; i < offset; i++) {
		if (input_context[i] == '\t')
			errordesc.append('\t', 1);
		else
			errordesc.append(' ', 1);
	}

	// Add a pointer to the error point
	errordesc.append(strlen(estring) + 3, "^ %s\n", estring);
#endif
	ERROR("XML Error '%s'", XML_ErrorString(XML_GetErrorCode(expat_parser)));
}


static const int xml_parser_buffer_size = 0x1000;

void 
c_xmldoc::parse_file(const char* file_name)
{
	int fd = -1;

	release_content();
	release_parser ();
	init_parser();

	fd = open(file_name, O_RDONLY);

	if (fd != -1) {
		for (;;) {
			int bytes_read;
			enum XML_Status status;

			void *buff = XML_GetBuffer(expat_parser, xml_parser_buffer_size);
			if (buff == NULL) {
				ERROR("cannot allocate XML parser buffer");
				goto end;
			}
			bytes_read = read(fd, buff, xml_parser_buffer_size);
			if (bytes_read < 0) {
				ERROR("cannot read '%s' (%d)", file_name, errno);
				goto end;

			} else if (bytes_read > 0) {
				status = XML_ParseBuffer(expat_parser, bytes_read, bytes_read == 0);
      
				switch (status) {
				case XML_STATUS_ERROR:
					xml_parsing_error();
					goto end;
				case XML_STATUS_SUSPENDED:
					close(fd);
					goto end;
				default:
					;
				}
			} else {
				break;
			}
		}
	}
 end:
	if (fd != -1)
		close(fd);
	cur_node = NULL;
}


void 
c_xmldoc::parse_string(const char* xml_as_string, int length)
{
	release_content();
	init_parser();
	if (length == 0)
		length = strlen(xml_as_string);
	if (length == 0) {
		root_node = NULL;
		cur_node = NULL;
		return;
	};
	if (XML_Parse(expat_parser, xml_as_string, length, true) != XML_STATUS_OK)
		xml_parsing_error();
	cur_node = NULL;
}


c_xmldoc::~c_xmldoc ()
{
	release_content();
	release_parser();
}


void 
c_xmldoc::release_content()
{
	if (root_node) {
		delete(root_node);
		root_node = NULL;
	}
	cur_node = NULL;
}


c_xmlnode* 
c_xmldoc::create(const char* root_node_name)
{
	root_node = new c_xmlnode(NULL, root_node_name);
	return(root_node);
}


c_xmlnode* 
c_xmldoc::root()
{
	return(root_node);
}


void 
c_xmldoc::save(const char* to_file)
{
	int fd = creat(to_file, 0600);
	int alen;
	string contents;

	if (fd == -1) {
		ERROR("cannot open file '%s' for writing (%d)", to_file, errno);
		return;
	}

	contents = as_string(true);
	alen = write(fd, contents.c_str(), strlen(contents.c_str()));
	close(fd);

	DEBUG(1, "Write %d bytes of XML to file '%s'", alen, to_file);
  
	if (alen != (int)strlen(contents.c_str())) {
		// This is odd, but lets just log it
		ERROR("write to '%s' truncated, %d bytes omitted", 
			  to_file, strlen(contents.c_str()) - alen);
	}
	
}

/*
 * expat catchers
 */
void 
c_xmldoc::xml_element_start(const char* element_name, 
							const char** attributes)
{
	c_xmlnode* tgt_node;

	if (cur_node == NULL) {
		tgt_node = new c_xmlnode(NULL, element_name);
		root_node = tgt_node;
	} else {
		// A node cannot have both textual and compound content
		tgt_node = cur_node->append_child(element_name);
	}
	for (int i = 0; attributes[i]; i += 2) 
		tgt_node->append_attribute (attributes[i], attributes[i + 1]);
	cur_node = tgt_node;
}


void 
c_xmldoc::xml_element_end(const char* element_name)
{
	// Sanity check
	if (!cur_node) {
		ERROR("document cannot start with element end");
		return;
	}
	if (strcmp(element_name, cur_node->name())) {
		ERROR("name mismatch '<%s>..</%s>", cur_node->name(), element_name);
		return;
	}
	
	if (trim_whitespace) 
		cur_node->trim_whitespace();

	cur_node = cur_node->parent();
}


void 
c_xmldoc::xml_character_data(const char* data, const int len)
{
	if (!cur_node || cur_node-> nbrof_children() > 0)
		return;
	cur_node->append_content(data, len);
}


void 
c_xmldoc::xml_cdata_start()
{
	if (cur_node)
		cur_node->set_cdata(true);	
}


void 
c_xmldoc::xml_cdata_end()
{
	if (cur_node)
		cur_node->set_cdata(false);	
}

static const char xml_hdr[] = "<?xml version=\"1.0\"?>\n";

string 
c_xmldoc::as_string (bool pretty_printing)
{
	string result(xml_hdr);

	if (root_node) {
		if (pretty_printing) {
			result.append(root_node->as_string(true, 4, 0));
		} else {
			result.append(root_node->as_string(false, 0, 0));
		}
	}
	return(result);
}
