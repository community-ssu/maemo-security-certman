// ------------------------------------------------------------------------
/// \file c_fstring.h
/// \brief The c_fstring class
//
// Revision $Id: c_fstring.h,v 1.6 2005/12/19 18:02:44 a2vepsal Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#ifndef C_FSTRING_DEF
#define C_FSTRING_DEF

/// \class c_fstring
/// \ingroup lowleveltools
/// \brief The flexible string class
///
/// This simple class implements a flexible string that grows 
/// automatically when needed. 

class c_fstring
{
 public:

  /// \brief Base constructor

  c_fstring ();

  /// \brief Copy constructor

  c_fstring (c_fstring& model);

  /// \brief Alternative constructor
  /// \param ini_value Initialize the string with this

  c_fstring (const char* ini_value);

  /// \brief Alternative constructor
  /// \param ini_value Initialize the string with this
  /// \param len The number of bytes to use from ini_value

  c_fstring (const char* ini_value, int len);

  /// \brief Destructor

  ~c_fstring ();

  /// \brief Append more data to the string
  /// \param data The data to append
  /// \param len The number of bytes to append

  void append (const char* data, int len);

  /// \brief Append a NULL-terminated string
  /// \param data The string to append

  void append (const char* data);

  /// \brief Append n copies of the given character
  /// \param c The character to append
  /// \param repeat How many times the character is repeated

  void append (char c, int repeat);

  /// \brief Append a formatted expression (as in sprintf)
  /// \param maxlen How much room is reserved for the
  /// new expression
  /// \param format (and more...) The format string, followed
  /// by values
  /// 
  /// If the formatted expression overflows the given number
  /// of bytes, the overflowing part is truncated

  void append (int maxlen, const char* format,...);

  /// \brief Append a formatted expression of at 
  /// most 256 characters
  /// \param format (and more...) The format string, followed
  /// by values

  void append_msg (const char* format,...);

  /// \brief Append the contents of a file
  /// \param file_name The name of the file to append

  void append_file (const char* file_name);

  /// \brief Empty the string

  void reset ();

  /// \brief Remove a section of the string
  /// \param start_point Remove characters starting from
  /// this position (starts from 0)
  /// \param nbrof_chars How many characters to remove
  ///
  /// If the given nbrof_chars overflows the string, all
  /// of the string from start_point to the end is discarded
  ///
  /// If the given starting position is equal or more than 
  /// the length of the string, an exception is thrown

  void remove (int start_point, int nbrof_chars);

  /// \brief Return a pointer to the start of the string
  /// \return A pointer. If more data is appended to the
  /// string, an earlierly returned pointer may no longer
  /// be valid.

  const char* as_string ();

  /// \brief Return a pointer to a string that contains
  /// the contents of the string escaped for XML, 
  /// i.e. special characters <>&'" are replaced
  /// by &lt;, &&gt; etc.
  /// \return A pointer to a XML-formatted string
  ///
  /// The returned pointer is managed by the c_fstring
  /// instance and must not be released by caller

  const char* as_xml_string ();

  /// \brief Convert the string to uppercase characters
  ///
  /// Note! Only 7-bit ASCII characters are converted

  void uppercase();

  /// \brief Trim leading and trailing whitespace away

  void trim();

  /// \brief Compare to a string
  /// \return true, if the strings are equal

  bool equals(const char* with_string);

 private:
  char* make_room (char** buf, int* len, int for_bytes, bool str_inited);
  char* str_buf;
  int str_buf_len;
  char* xml_buf;
  int xml_buf_len;
};
#endif
