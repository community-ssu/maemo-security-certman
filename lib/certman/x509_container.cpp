/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/// \cond Don't make doxygen documentation

#include "x509_container.h"
#include <maemosec_certman.h>

namespace maemosec {

	x509_container::x509_container(const char* pathname)
	{
		FILE* fp = fopen(pathname, "r");

		MAEMOSEC_DEBUG(2, "Loading %s", pathname);

		m_handled = false;
		m_verified = false;
		m_cert = NULL;
		m_bio = NULL;
		if (fp) {
			m_cert = PEM_read_X509(fp, NULL, 0, NULL);
			fclose(fp);
			if (m_cert)
				analyze_cert();
			else {
				MAEMOSEC_ERROR("cannot load certificate from '%s'", pathname);
			}
		} else
			MAEMOSEC_ERROR("cannot find file '%s' (%d)", pathname, errno);

	}


	x509_container::~x509_container()
	{
		if (m_cert)
			X509_free(m_cert);
		if (m_bio)
			BIO_free(m_bio);
	}


	bool
	x509_container::get_extension(int nid, string& to_buf)
	{
		char buf [255];
		X509_EXTENSION *ext;
		int pos, len;

		pos = X509_get_ext_by_NID(m_cert, nid, -1);
		if (-1 == pos) {
			MAEMOSEC_DEBUG(2, "NID %d does not exist in this certificate", nid);
			return(false);
		}

		ext = sk_X509_EXTENSION_value(m_cert->cert_info->extensions, pos);
		if (NULL == ext) {
			MAEMOSEC_ERROR("Attribute %d not found", pos);
			return(false);
		}

		if (NULL == m_bio) {
			m_bio = BIO_new(BIO_s_mem());
			if (!m_bio) {
				MAEMOSEC_ERROR("cannot create new BIO");
				return(false);
			}
		}

		X509V3_EXT_print(m_bio, ext, 0, 0);
		len = BIO_gets(m_bio, buf, sizeof(buf));

		if (len && buf[len - 1] == '\n')
			buf[len - 1] = '\0';
		
		to_buf = buf;

		/*
		 * Flush the BIO if there is more data than fits
		 * the buffer.
		 */
		while (sizeof(buf) == BIO_gets(m_bio, buf, sizeof(buf)));

		return(true);
	}

	#define KEYID_PFIX "keyid:"

	void 
	x509_container::analyze_cert()
	{
		char name_buf[1024];

		m_subject_name = X509_NAME_oneline(X509_get_subject_name(m_cert), 
										   name_buf, sizeof(name_buf));

		MAEMOSEC_DEBUG(1, "Analyzing '%s'", m_subject_name.c_str());

		m_issuer_name = X509_NAME_oneline(X509_get_issuer_name(m_cert), 
										  name_buf, sizeof(name_buf));

		if (!get_extension(NID_subject_key_identifier, m_key_id)) {

			MAEMOSEC_DEBUG(1, "Subject key id not defined!");

			maemosec_key_id key_id;
			if (0 == maemosec_certman_get_key_id(m_cert, key_id)) {
				for (int i = 0; i < MAEMOSEC_KEY_ID_LEN; i++) {
					char tmp[3];
					sprintf(tmp, "%02X", key_id[i]);
					if (i)
						m_key_id.append(":");
					m_key_id.append(tmp);
				}
			}
		}
		if (!get_extension(NID_authority_key_identifier, m_issuer_key_id)) {
			MAEMOSEC_DEBUG(1, "Authority key id not defined");

		} else {
			/*
			 * Remove "keyid:" prefix if exists, otherwise set empty
			 */
			if (0 == memcmp(m_issuer_key_id.c_str(), KEYID_PFIX, strlen(KEYID_PFIX)))
				m_issuer_key_id.erase(0, strlen(KEYID_PFIX));
			else
				m_issuer_key_id = "";
		}
		MAEMOSEC_DEBUG(2, "\nkey_id       = %s\nissuer_key_id= %s\n%s self signed", 
					   m_key_id.c_str(), m_issuer_key_id.c_str(),
					   is_self_signed()?"is":"is not");
		BIO_free(m_bio);
		m_bio = NULL;
	}


	bool 
	x509_container::is_issued_by(X509* cert)
	{
		X509_STORE* tmp_store;
		X509_STORE_CTX *csc;
		bool retval;
		int rc;

		tmp_store = X509_STORE_new();
		X509_STORE_add_cert(tmp_store, cert);

		csc = X509_STORE_CTX_new();
		rc = X509_STORE_CTX_init(csc, tmp_store, m_cert, NULL);

		retval = (X509_verify_cert(csc) > 0);
		if (!retval) {
			MAEMOSEC_DEBUG(1, "Verification files because of %d", csc->error);
		}
		X509_STORE_CTX_free(csc);
		X509_STORE_free(tmp_store);

		return(retval);
	}


	bool 
	x509_container::is_self_signed()
	{
		bool retval;

		MAEMOSEC_DEBUG(1, "Check if '%s' is self signed", 
					   m_subject_name.c_str());

		retval = is_issued_by(m_cert);

		MAEMOSEC_DEBUG(1, "'%s' %s self signed", 
					   m_subject_name.c_str(), 
					   retval?"is":"is not");

		if (retval && "" == m_issuer_key_id)
			m_issuer_key_id = m_key_id;

		return(retval);
	}


	void
	x509_container::set_issuer(x509_container* to_this)
	{
		m_issuer_name = to_this->m_subject_name;
		m_issuer_key_id = to_this->m_key_id;
	}


	void
	x509_container::print(void)
	{
		PEM_write_X509(stdout, m_cert);
	}
}
/// \endcond
