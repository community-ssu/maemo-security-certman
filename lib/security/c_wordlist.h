// ------------------------------------------------------------------------
/// \file c_wordlist.h
/// \brief The c_wordlist class
//
// Revision $Id: c_wordlist.h,v 1.6 2005/01/03 07:00:03 jum Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#ifndef C_WORDLIST_DEF
#define C_WORDLIST_DEF

#include "c_farray"
#include "c_fstring.h"

/// \class c_wordlist
/// \ingroup lowleveltools
/// \brief A flexible string array
///
/// This class can be used to store a set of strings
/// or it can be used to parse strings by splitting them
/// at whitespace

class c_wordlist {
 public:

  /// \brief Base constructor

  c_wordlist();

  /// \brief An alternative constructor
  /// \param from_text A string that is split into words
  /// \param len The number of bytes in the text, if 0,
  /// strlen(from_text) is assumed

  c_wordlist(const char* from_text, int len);

  /// \brief Destructor

  ~c_wordlist();

  /// \brief Parse a string by splitting it at whitespace
  /// \param from_text The text to be parsed
  /// \param len The number of bytes to be parsed. If 0,
  /// strlen(from_text) is assumed

  void parse(const char* from_text, int len);

  /// \brief Add a word to the list
  /// \param word The string to be added

  void add(const char* word);

  /// \brief Does the list contain the given string
  /// \param word The searched string
  /// \return true, if the list contains the given string

  bool contains(const char* word);

  /// \brief How many words the list contains
  /// \return The number of words in the list

  int nbrof_words();

  /// \brief Return the word at the given position
  /// \param pos The position, starting at 0
  /// \return A pointer to the given word
  ///
  /// If the given position is out-of-bounds, and
  /// exception is thrown

  const char* word(int pos);

  /// \brief Return the contents of the list as a comma-separated
  /// string
  /// \return A pointer to the string
  ///
  /// The returned pointer must not be deallocated by caller

  const char* as_string();

  /// \brief Empty the list

  void reset();

 private:
  c_farray<c_fstring> words;
  c_fstring str_buf;
};

#endif
