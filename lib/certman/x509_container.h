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

/**
 * \file x509_container.h
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

#include "maemosec_common.h"

namespace maemosec {

    /** 
	 * \class x509_container_cert 
	 * \brief A helper class to sort and analyze X509 certificates
	 */
	class x509_container 
	{
		/// \cond
        //  Don't make doxygen documentation 
	private:
		X509* m_cert;
		void analyze_cert();
		bool get_extension(int nid, string& to_buf);
		string m_subject_name;
		string m_issuer_name;
		string m_key_id;
		string m_issuer_key_id;
		BIO* m_bio;

	public:
		bool m_handled;
		bool m_verified;
		x509_container(const char* pathname);
		~x509_container();
		X509* cert() {return(m_cert);};
		const char* subject_name() {return(m_subject_name.c_str());};
		const char* issuer_name() {return(m_issuer_name.c_str());};
		const char* key_id() {return(m_key_id.c_str());};
		const char* issuer_key_id() {return(m_issuer_key_id.c_str());};
		bool is_self_signed();
		bool is_issued_by(X509* cert, int* error);
		void set_issuer(x509_container* to_this);
		void print();
		/// \endcond
	};
}
