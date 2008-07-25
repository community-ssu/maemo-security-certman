// ------------------------------------------------------------------------
/// \file c_xmldoc.cpp
/// \brief The implementation of the c_xmldoc class
//
// Revision $Id: c_xmldoc.cpp,v 1.9 2005/06/30 10:34:23 a2vepsal Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

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

static void XMLCALL _exp_element_start (void* user_data, 
					const XML_Char* el, 
					const XML_Char** attr)
{
  c_xmldoc* to_doc = (c_xmldoc*) user_data;

  if (to_doc) {
    // Quick&dirty: cast XML_Char directly to char
    to_doc-> xml_element_start ((char*) el, (char**) attr);
    return;
  };
  // DEBUG
  printf ("Element start %s\n", el);
  for (int i = 0; attr[i]; i += 2) 
    printf ("  Attribute %s=%s\n", attr[i], attr[i + 1]);
}


static void XMLCALL _exp_element_end (void* user_data, const XML_Char* el)
{
  c_xmldoc* to_doc = (c_xmldoc*) user_data;

  if (to_doc) {
    // Quick&dirty: cast XML_Char directly to char
    to_doc-> xml_element_end ((char*) el);
    return;
  };
  // DEBUG
  printf ("Element end %s\n", el);
}

static void XMLCALL _exp_character_data (void* user_data, 
					 const XML_Char* data, 
					 int len)
{
  c_xmldoc* to_doc = (c_xmldoc*) user_data;

  if (to_doc) {
    // Quick&dirty: cast XML_Char directly to char
    to_doc-> xml_character_data ((char*) data, len);
    return;
  };

  // DEBUG
  int i;
  if (data && len) {
    printf ("  Content ");
    for (i = 0; i < len; i++)
      printf ("%c", *data++);
  }
  printf ("\n");
}


static void XMLCALL _exp_start_cdata (void* user_data)
{
  c_xmldoc* to_doc = (c_xmldoc*) user_data;
  to_doc->xml_cdata_start();
}


static void XMLCALL _exp_end_cdata (void* user_data)
{
  c_xmldoc* to_doc = (c_xmldoc*) user_data;
  to_doc->xml_cdata_end();
}


// Class members
// -------------

c_xmldoc :: c_xmldoc ()
{
  root_node = NULL;
  cur_node = NULL;
  xml_str_buf = NULL;
  expat_parser = NULL;
  trim_whitespace = false;
}


void c_xmldoc :: init_parser()
{
  if (expat_parser == NULL) {
    expat_parser = XML_ParserCreate(NULL);
    XML_SetStartElementHandler(expat_parser, _exp_element_start);
    XML_SetEndElementHandler(expat_parser, _exp_element_end);
    XML_SetCharacterDataHandler(expat_parser, _exp_character_data);
    XML_SetCdataSectionHandler(expat_parser, _exp_start_cdata, _exp_end_cdata);
    XML_SetUserData (expat_parser, (void*) this);
  };
}


void c_xmldoc :: release_parser ()
{
  if (expat_parser) {
    XML_ParserFree(expat_parser);
    expat_parser = NULL;
  };
}


void c_xmldoc :: xml_parsing_error()
{
  c_fstring errordesc;
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
  };

  // Truncate to the next newline after error
  for (i = offset; i < size; i++) {
    if (input_context[i] == '\n')
      size = i;
  };

  // Add context
  errordesc.append(1 + size, "%s\n", input_context);
  for (i = prefix; i < offset; i++) {
    if (input_context[i] == '\t')
      errordesc.append('\t', 1);
    else
      errordesc.append(' ', 1);
  };

  // Add a pointer to the error point
  errordesc.append(strlen(estring) + 3, "^ %s\n", estring);
  ERROR("%s",errordesc.as_string());
}


#define BUFF_SIZE 4096

void c_xmldoc :: parse_file (const char* file_name)
{
  int fd;

  reset_content();
  release_parser ();
  init_parser();

  fd = open(file_name, O_RDONLY);

  if (fd != -1) {
#if 0
   if (strlen(file_path.as_string()) == 0)    
      full_path(file_name, file_path);
#endif
    for (;;) {
      int bytes_read;
      enum XML_Status status;

      void *buff = XML_GetBuffer(expat_parser, BUFF_SIZE);
      if (buff == NULL) {
	/* handle error... */
	close(fd);
	return;
      }
       bytes_read = read(fd, buff, BUFF_SIZE);
      if (bytes_read < 0) {
	/* handle error... */
	close(fd);
	return;
      }
      status = XML_ParseBuffer(expat_parser, bytes_read, bytes_read == 0);
      
      switch (status) {
	case XML_STATUS_ERROR:
	  /* handle error... */
	  close(fd);
	  xml_parsing_error();
	  return;
	case XML_STATUS_SUSPENDED:
	  close(fd);
	  return;
	default:
	  ;
      };
      if (bytes_read == 0) {
	close(fd);
	return;
      };
    }
    close (fd);
  };
  cur_node = NULL;
}


void c_xmldoc :: parse_string (const char* xml_as_string, int length)
{
  reset_content();
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


c_xmldoc :: ~c_xmldoc ()
{
  reset_content();
  release_parser();
  if (xml_str_buf)
    free(xml_str_buf);
}


void c_xmldoc :: reset_content()
{
  if (root_node) {
    root_node-> reset();
    delete(root_node);
    root_node = NULL;
  };
  cur_node = NULL;
}


c_xmlnode* c_xmldoc :: create (const char* root_node_name)
{
  root_node = new c_xmlnode(this, NULL, root_node_name);
  return root_node;
}


c_xmlnode* c_xmldoc :: root()
{
  return root_node;
}


const char* c_xmldoc :: xml_file_path()
{
  return file_path.as_string();
}


void c_xmldoc :: save(const char* to_file)
{
  int fd = creat(to_file, 0600);
  int alen;
  const char* data;

  if (!fd) {
    ERROR("cannot open file '%s' for writing (%d)", to_file, errno);
  };

  data = as_string(true);
  alen = write(fd, data, strlen(data));
  close(fd);

  DEBUG(1, "Writing XML to file %s/n data: %s/n", to_file, data);
  
  if (alen != (int)strlen(data)) 
    // This is odd, but lets just log it
    ERROR("write truncated to '%s', %d bytes omitted", 
	     to_file, strlen(data) - alen);

  free(xml_str_buf);
  xml_str_buf = NULL;

  // Remember the file name
#if 0
  if (strlen(file_path.as_string()) == 0)
    full_path(to_file, file_path);
#endif
}


void c_xmldoc :: save()
{
  if (strlen(file_path.as_string())) {
    save(file_path.as_string());
  } else {
    ERROR("cannot save, no file name defined");
  };
}


c_xmlnode* c_xmldoc :: navigate (const char* xpath, bool required)
{
  if (!xpath || strlen(xpath) == 0) {
    if (!cur_node) {
      ERROR("empty xpath expression");
    } else
      return cur_node;
  };

  if (cur_node == NULL)
    cur_node = root_node;

  if (cur_node)
    return cur_node->navigate(xpath, required);
  else
    return NULL;
}


void c_xmldoc :: xml_element_start (char* element_name, char** attributes)
{
  c_xmlnode* tgt_node;

  if (cur_node == NULL) {
    tgt_node = new c_xmlnode(this, NULL, element_name);
    root_node = tgt_node;
  } else {
    // A node cannot have both textual and compound content
    cur_node-> reset_content();
    tgt_node = cur_node-> append_child(element_name);
  };

  for (int i = 0; attributes[i]; i += 2) 
    tgt_node->append_attribute (attributes[i], attributes[i + 1]);

  cur_node = tgt_node;
}


void c_xmldoc :: xml_element_end (char* element_name)
{
  // Sanity check
  if (!cur_node)
    // ERROR: document cannot start with element end
    return;
  if (strcmp(element_name, cur_node->name()))
    // ERROR: names do not match
    return;

  if (trim_whitespace) 
    cur_node->trim_whitespace();

  cur_node = cur_node-> parent();
}


void c_xmldoc :: xml_character_data (char* data, int len)
{
  if (!cur_node || cur_node-> nbrof_children() > 0)
    return;

  cur_node-> append_content(data, len);
}


void c_xmldoc :: xml_cdata_start()
{
  if (cur_node)
    cur_node->set_cdata(true);	
}


void c_xmldoc :: xml_cdata_end()
{
  if (cur_node)
    cur_node->set_cdata(false);	
}

static const char xml_hdr[] = "<?xml version=\"1.0\"?>";

const char* c_xmldoc :: as_string (bool pretty_printing)
{
  c_fstring* tmp;
  int mlen;

  if (xml_str_buf)
    free (xml_str_buf);

  if (root_node) {
    if (pretty_printing)
      // Indent with two spaces
      tmp = root_node-> as_fstring(true, 2, 0);
    else
      tmp = root_node-> as_fstring(false, 0, 0);
    mlen = strlen(xml_hdr) + strlen(tmp->as_string()) + 2;
    xml_str_buf = (char*) malloc(mlen);
    strcpy (xml_str_buf, xml_hdr);
    if (pretty_printing)
      strcat(xml_str_buf, "\n");
    strcat (xml_str_buf, tmp->as_string());
    delete(tmp);
    return xml_str_buf;
  } else
    return "";
}
