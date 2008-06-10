/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
 * \file ngcm_x509_cert.h
 * \brief A helper class to parse and analyze certificates
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>

// STL headers
#include <string>
#include <vector>
#include <stack>
#include <map>
using namespace std;

// OpenSSL headers
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "sec_common.h"

/** 
 * \class ngcm_x509_cert 
 * \brief A helper class to sort and analyze X509 certificates
 */
class ngcm_x509_cert 
{
    /// \cond
    //  Don't make doxygen documentation 
private:
	X509* m_cert;
	ngcm_x509_cert* m_issuer;
	void analyze_cert();
	string m_subject_name;
	string m_key_id;
	string m_issuer_key_id;

public:
	bool m_handled;
	bool m_verified;
	ngcm_x509_cert(const char* pathname);
	~ngcm_x509_cert();
	X509* cert() {return(m_cert);};
	ngcm_x509_cert* issuer() {return(m_issuer);};
	const char* subject_name() {return(m_subject_name.c_str());};
	const char* key_id() {return(m_key_id.c_str());};
	const char* issuer_key_id() {return(m_issuer_key_id.c_str());};
	void set_issuer(ngcm_x509_cert* to_this);
	void print();
    /// \endcond
};
