/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/// \cond Don't make doxygen documentation

#include "x509_container.h"

namespace maemosec {

	x509_container::x509_container(const char* pathname)
	{
		FILE* fp = fopen(pathname, "r");

		m_handled = false;
		m_verified = false;
		m_cert = NULL;
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

		MAEMOSEC_DEBUG(2, "created new %p(%p)", this, m_cert);
	}

	x509_container::~x509_container()
	{
		MAEMOSEC_DEBUG(2, "erasing %p(%p)", this, m_cert);
		if (m_cert)
			X509_free(m_cert);
	}

	void 
	x509_container::analyze_cert()
	{
		char buf[256];
		int i, len;
		STACK_OF(X509_EXTENSION) *exts;
		BIO* m_bio;
		
		m_subject_name = X509_NAME_oneline(X509_get_subject_name(m_cert),
										   buf, sizeof(buf));

		// A little bit ugly to go directly into the struct, but there seems
		// not to be a cleaner way.
		exts = m_cert->cert_info->extensions;

		if (!exts)
			return;

		m_bio = BIO_new(BIO_s_mem());
		if (!m_bio) {
			MAEMOSEC_ERROR("cannot create new BIO");
			return;
		}

		for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
			// ASN1_OBJECT *obj;
			X509_EXTENSION *ext;
			const char* ext_name;
			char* c;

			MAEMOSEC_DEBUG(2, "extension %d", i);
			ext = sk_X509_EXTENSION_value(exts, i);
			ext_name = OBJ_nid2ln(OBJ_obj2nid(ext->object));
			X509V3_EXT_print(m_bio, ext, 0, 0);
			len = BIO_gets(m_bio, buf, sizeof(buf));
			MAEMOSEC_DEBUG(2, "got %d bytes", len);
			if (len && buf[len - 1] == '\n')
				buf[len - 1] = '\0';
			MAEMOSEC_DEBUG(3, "%s=%s", ext_name, buf);

			// TODO: The ordering should really be made according to issuer 
			// name and serial number.

			if (strcmp(ext_name, "X509v3 Subject Key Identifier") == 0)
				m_key_id = buf;
			else if (strcmp(ext_name, "X509v3 Authority Key Identifier") == 0) {
				if (memcmp(buf, "keyid:", 6) == 0)
					c = &buf[6];
				else
					c = buf;
				m_issuer_key_id = c;
			}
		}
		BIO_free(m_bio);
	}

	void
	x509_container::print(void)
	{
		PEM_write_X509(stdout, m_cert);
	}
}
/// \endcond
