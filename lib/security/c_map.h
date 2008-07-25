// ------------------------------------------------------------------------
/// \file c_map.h
/// \brief The c_map class
//
// Revision $Id: c_map.h,v 1.5 2005/01/03 07:00:03 jum Exp $
//
// ------------------------------------------------------------------------
// (C) Copyright Nokia 2004
// ------------------------------------------------------------------------

#ifndef C_MAP_DEF
#define C_MAP_DEF

#include "c_fstring.h"
#include "c_farray"

/// \class c_map
/// \ingroup lowleveltools
/// \brief A string name/value -pair map
/// 
/// The map can be either case-sensitive or 
/// case-insensitive. In the latter case the
/// key values are converted to uppercase before
/// they are stored into the map
///
/// The map allocates own buffers to the stored
/// values, so it is perfectly all right to store
/// values from local stack or give pointers to
/// string constants. The given names and values
/// are NUL-terminated.

class c_map {
 public:

  /// \brief Constructor
  /// \param case_sensitive If true, the key values
  /// must match exactly, otherwise the comparision
  /// is case-insensitive (7-bit ASCII characters only)

  c_map(bool case_sensitive);

  /// \brief Deconstructor

  ~c_map();

  /// \brief Map a key to a value
  /// \param key The key
  /// \param value The value
  /// \param override If the map already contains the given
  /// key, it's current value is overridden. Otherwise the
  /// new value is ignored.

  void map(const char* key, const char* value, bool override);

  /// \brief Map a key to a value
  /// \param key The key
  /// \param value The value
  ///
  /// If the map already contains the given
  /// key, it's current value is overridden.

  void map(const char* key, const char* value);

  /// \brief Map a key to a value
  /// \param key The key
  /// \param value The value
  /// \param bytes The number of bytes stored from the value
  ///
  /// If the map already contains the given
  /// key, it's current value is overridden.

  void map(const char* key, const char* value, int bytes);

  /// \brief Map an key to an integer value
  /// \param key The key
  /// \param value The value
  ///
  /// If the map already contains the given
  /// key, it's current value is overridden.
  ///
  /// The value stored in the map is converted to a string

  void map(const char* key, long value);

  /// \brief Remove a mapping
  /// \param key The key to be removed
  /// 
  /// If the map already does not contain the given
  /// key, nothing is done.

  void unmap(const char* key);

  /// \brief Does a map contain the given key
  /// \param key The key
  /// \return true, if the map contains the given key

  bool contains(const char* key);

  /// \brief Return a value identified by the key
  /// \param key The key
  /// \param required If the map does not contain the
  /// given key and this parameter is true, and exception
  /// is thrown
  /// \param defval If the map does not contain the given key
  /// and required is false, this value is returned
  /// \return The mapped value or the defval, is no given
  /// key is found

  const char* value(const char* key, bool required, const char* defval);

  /// \brief How many key-name pairs the map contains
  /// \return The number of key-name pairs

  int nbrof_values();

  /// \brief Return the key in the given position
  /// \param of_pos The order number of the key, starting from 0
  
  const char* key_value(int of_pos);

  /// \brief Return the value in the given position
  /// \param of_pos The order number of the value, starting from 0
  
  const char* mapped_value(int of_pos);


  /// \brief Check if the value mapped to the given key
  /// equals to the given string
  /// \param value_mapped_to_key The key
  /// \param with_string The string to compare the value with
  /// \param case_sensitive Is the comparison case-sensitive or not
  /// \return true, if the map contains a value mapped to the
  /// given key and the value is equal to the given string

  bool equals(char* value_mapped_to_key, 
	      char* with_string, 
	      bool case_sensitive);

  /// \brief Empty the map

  void reset();

 private:
  int key_pos (const char* of_key);
  c_farray<c_fstring> keys;
  c_farray<c_fstring> vals;
  bool use_strcmpi;
};

#endif
