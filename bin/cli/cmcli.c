// -*- mode:c; tab-width:4; c-basic-offset:4; -*-
/**
 \file cmcli.c
 \ingroup libcertman
 \brief A command-line utility for managing certificate stores

 This command-line utility can be used to list contents of certificate 
 stores, create new stores and manipulate the existing ones by adding
 and deleting certificates in them. It also serves as an example of how
 to use the certman library.
 
*/


#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/pem.h>

/**
 * \def sk_STORE_OBJECT_num(st)
 * \brief This macro is normally defined in openssl/safestack.h, 
 * but not in the scratchbox osso-98 version of OpenSSL, so define 
 * it here if not yet defined.
 */
#ifndef sk_STORE_OBJECT_num
#define sk_STORE_OBJECT_num(st) SKM_sk_num(STORE_OBJECT, (st))
#endif

#include <maemosec_certman.h>
#include <maemosec_common.h>

/**
 * \var debug_level
 * \brief Increment this variable to produce more debug output to stdout
 */
extern int debug_level;

/*
 * Global options
 */
static int force_opt = 0;

/*
 * Utilities. Should be added to libmaemosec_certman0
 */
static int
report_openssl_error(const char* str, size_t len, void* u)
{
	char* tmp = strrchr(str, '\n');
	if (tmp && ((tmp - str) == strlen(str)))
		*tmp = '\0';
	MAEMOSEC_DEBUG(1, "OpenSSL error '%s'", str);
	ERR_clear_error();
	return(0);
}


static const char*
determine_filetype(FILE* fp, void** idata)
{
	X509* cert;
	PKCS12* cont;
	X509_SIG* ekey;

	rewind(fp);
	cert = PEM_read_X509(fp, NULL, 0, NULL);
	if (cert) {
		*idata = (void*)cert;
		return("X509-PEM");
	} else
		MAEMOSEC_DEBUG(1, "Not a PEM file");

	rewind(fp);
	cert = d2i_X509_fp(fp, NULL);
	if (cert) {
		*idata = (void*)cert;
		return("X509-DER");
	} else
		MAEMOSEC_DEBUG(1, "Not a DER file");

	rewind(fp);
	cont = d2i_PKCS12_fp(fp, NULL);
	if (cont) {
		*idata = (void*)cont;
		return("PKCS12");
	} else
		MAEMOSEC_DEBUG(1, "Not a PKCS12 file");

	rewind(fp);

	ekey = d2i_PKCS8_fp(fp, NULL);
	if (cont) {
		*idata = (void*)ekey;
		return("PKCS8");
	} else
		MAEMOSEC_DEBUG(1, "Not a PKCS8 file");

	return("Unknown");
}


static void
usage(void)
{
	printf(
		"Usage:\n"
		"cmcli [-t <domain>[:<domain>...]] [-<c|p> <domain>] -a <cert-file>\n"
		"       -v <cert-file> -r <num> [-D*] [-L] [-f]\n"
		" -T to specify shared domains of trusted signing certificates\n"
		" -t to specify private domains of trusted signing certificates\n"
		" -v to verify a certificate against the trusted domains\n"
		" -c to open/create a shared domain for modifications\n"
		" -p to open/create a private domain for modifications\n"
		" -a to add a certificate to the given domain\n"
		" -r to remove the nth certificate from the given domain\n"
		" -L to list all certificates and keys\n"
		" -D, -DD... to increase level of debug info shown\n"
		" -f to force an operation despite warnings\n"
		);
}


static void
print_key_id(maemosec_key_id key_id, const char* to_buf, unsigned max_len)
{
	unsigned i;

	if (max_len < 3*MAEMOSEC_KEY_ID_LEN)
		return;
	for (i = 0; i < MAEMOSEC_KEY_ID_LEN; i++) {
		sprintf(to_buf, "%s%02X", i?":":"", key_id[i]);
		to_buf += strlen(to_buf);
	}
}


static int
show_cert(int pos, X509* cert, void* x)
{
	char buf[255], keybuf[64], *name;
	maemosec_key_id key_id;
	int i;

	if (!cert)
		return(ENOENT);

	name = X509_NAME_oneline(X509_get_subject_name(cert),
							 buf, 
							 sizeof(buf));

	if (0 == maemosec_certman_get_key_id(cert, key_id))
		print_key_id(key_id, keybuf, sizeof(keybuf));
	else
		strcpy(keybuf, "??:??:??:??:??:??:??:??:??:??:??:??:??:??:??:??:??:??:??:??");

	if (pos >= 0) 
		printf("%3d: %s %s\n", pos, keybuf, name);
	else {
		if (pos < -1) {
			if (pos < -2)
				for (i = -2; i > pos; i--)
					printf("   ");
			printf("+->");
		}
		printf("%s\n", name);
	}
	return(0);
}


static int
show_key(int pos, maemosec_key_id key_id, void* ctx)
{
	char keybuf[64];
	print_key_id(key_id, keybuf, sizeof(keybuf));
	printf("%3d: %s\n", pos, keybuf);
	return(0);
}


static int 
is_self_signed(X509* cert)
{
	char buf1[255];
	char buf2[255];

	if (!cert)
		return(0);
	/*
	 * How exactly this should be done...
	 */
	MAEMOSEC_DEBUG(1, "name = %s\nissuer = %s\ncert type = %x", 
				   X509_NAME_oneline(X509_get_subject_name(cert), buf1, sizeof(buf1)),
				   X509_NAME_oneline(X509_get_issuer_name(cert), buf2, sizeof(buf2)),
				   X509_certificate_type(cert, NULL));
	if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0) {
		MAEMOSEC_DEBUG(1, "is self signed");
		return(1);
	} else {
		MAEMOSEC_DEBUG(1, "is not self signed");
		return(0);
	}
}


static int
verify_cert(X509_STORE* store, X509* cert)
{
	X509_STORE_CTX *csc;
	int retval;
	int rc;

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		fprintf(stderr, "ERROR: cannot create new context\n");
		return(0);
	}

	rc = X509_STORE_CTX_init(csc, store, cert, NULL);
	if (rc == 0) {
		fprintf(stderr, "ERROR: cannot initialize new context\n");
		return(0);
	}

	retval = (X509_verify_cert(csc) > 0);

	if (retval) {
		int i;
		printf("Trust chain:\n");
		for (i = sk_X509_num(csc->chain); i > 0; i--) {
			X509* issuer = sk_X509_value(csc->chain, i - 1);
			if (issuer) {
				show_cert(i - sk_X509_num(csc->chain) - 1, issuer, NULL);
			}
		}
	}
	X509_STORE_CTX_free(csc);
	return(retval);
}


static X509*
get_cert(const char* from_file)
{
	FILE* fp;
	X509* cert;

	fp = fopen(from_file, "r");
	if (!fp) {
		fprintf(stderr, "Cannot read '%s' (%d)\n", from_file, errno);
		return(0);
	}
	cert = PEM_read_X509(fp, NULL, 0, NULL);
	if (!cert) {
		fprintf(stderr, "Cannot read certificate from '%s'\n", from_file);
	}
	fclose(fp);
	return(cert);
}


static int
add_cert_to_domain(domain_handle to_domain, X509* cert, X509_STORE* to_certs)
{
	X509* my_cert;
	char buf[255], *name;
	int rc;

	name = X509_NAME_oneline(X509_get_subject_name(cert),
							 buf, 
							 sizeof(buf));

	/* 
	 * If the certificate is not self signed, try to
	 * verify it. By default, do not allow adding it 
	 * if the verification fails.
	 */
	if (!is_self_signed(cert) && !verify_cert(to_certs, cert)) { 
		fprintf(stderr, 
				"%s\nWARNING: certificate fails verification\n",
				name);
		if (!force_opt) 
			return(0);
		else
			fprintf(stderr, 
					"WARNING: adding unverifiable certificate\n%s\n",
					name);
	}
	rc = maemosec_certman_add_cert(to_domain, cert);
	if (0 == rc) {
		printf("Added %s\n", name);
		return(1);
	} else {
		fprintf(stderr, "ERROR: cannot add '%s' (%d)\n", name, rc);
		return(0);
	}
}

typedef enum {cmd_add, cmd_verify, cmd_none} multi_arg_cmd;

/**
 * \brief The main program
 * Execute the command without any parameters to get the help
 */

int
main(int argc, char* argv[])
{
	int rc, i, a, pos, flags;
	domain_handle my_domain = NULL;
	X509_STORE* certs = NULL;
	X509* my_cert = NULL;
	multi_arg_cmd ma_cmd = cmd_none;

	if (1 == argc) {
		usage();
		return(-1);
	}

	rc = maemosec_certman_open(&certs);
	if (rc != 0) {
		fprintf(stderr, "ERROR: cannot open certificate repository (%d)\n", rc);
		return(-1);
	}

    while (1) {
		a = getopt(argc, argv, "t:T:c:p:a:v:r:DLKfi:h");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
		case 'D':
			debug_level++;
			break;

		case 'T':
		case 't':
			rc = maemosec_certman_collect(optarg, ('T' == a), certs);
			if (rc != 0) {
				fprintf(stderr, "ERROR: cannot open domain '%s' (%d)\n", 
						optarg, rc);
				return(-1);
			}
			break;

		case 'v':
			my_cert = get_cert(optarg);
			if (my_cert) {
				if (verify_cert(certs, my_cert))
					printf("Verified OK\n");
				else 
					printf("Verification fails\n");
				X509_free(my_cert);
			}
			ma_cmd = cmd_verify;
			break;

		case 'L':
			for (i = 0; i < sk_STORE_OBJECT_num(certs->objs); i++) {
				X509_OBJECT* obj = sk_X509_OBJECT_value(certs->objs, i);
				if (obj->type == X509_LU_X509) {
					show_cert(i, obj->data.x509, NULL);
				}
			}
			break;

		case 'c':
		case 'p':
			if ('c' == a)
				flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;
			else
				flags = MAEMOSEC_CERTMAN_DOMAIN_PRIVATE;
			rc = maemosec_certman_open_domain(optarg, flags, &my_domain);
			if (0 != rc) {
				fprintf(stderr, "ERROR: cannot open/create domain '%s' (%d)\n", 
						optarg, rc);
				return(-1);
			} else if (0 < maemosec_certman_nbrof_certs(my_domain)) {
				maemosec_certman_collect(optarg, flags, certs);
			}
			break;

		case 'a':
			if (!my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			my_cert = get_cert(optarg);
			if (my_cert) {
				char buf[255], *name;

				name = X509_NAME_oneline(X509_get_subject_name(my_cert),
										 buf, 
										 sizeof(buf));

				/* 
				 * If the certificate is not self signed, try to
				 * verify it. By default, do not allow adding it 
				 * if the verification fails.
				 */
				if (   !is_self_signed(my_cert) 
					&& !verify_cert(certs, my_cert)) 
				{
					fprintf(stderr, 
							"%s\nWARNING: certificate fails verification\n",
							name);
					if (!force_opt) {
						X509_free(my_cert);
						return(-1);
					} else
						fprintf(stderr, 
								"WARNING: adding unverifiable certificate\n%s\n",
								name);
				}
				rc = maemosec_certman_add_cert(my_domain, my_cert);
				if (0 == rc)
					printf("Added %s\n", name);
				else
					fprintf(stderr, "ERROR: cannot add '%s' (%d)\n",
							name, rc);
				X509_free(my_cert);
			}
			ma_cmd = cmd_add;
			break;

		case 'r':
			if (my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			pos = atoi(optarg);
			if (pos < 0 || pos >= maemosec_certman_nbrof_certs(my_domain)) {
				fprintf(stderr, 
						"ERROR: domain does not contain certificate #%d\n",
						pos);
				goto end;
				
			}
			rc = maemosec_certman_rm_cert(my_domain, pos);
			if (0 != rc) {
				fprintf(stderr, "ERROR: cannot remove certificate #%d (%d)\n",
							pos, rc);
			}
			break;

		case 'K':
			printf("Private keys:\n");
			maemosec_certman_iterate_keys(show_key, NULL);
			break;

		case 'f':
			force_opt++;
			break;

		case 'i':
			install_file(get_cert(optarg));
			break;

		default:
			usage();
			return(-1);
		}
	}

	if (optind < argc) {
		for (i = optind; i < argc; i++) {
			switch (ma_cmd) 
				{
				case cmd_add:
					if (!my_domain) {
						printf("ERROR: no domain defined\n");
						goto end;
					}
					my_cert = get_cert(argv[i]);
					if (my_cert) {
						add_cert_to_domain(my_domain, my_cert, certs);
						X509_free(my_cert);
					}
					break;
				case cmd_verify:
					my_cert = get_cert(argv[i]);
					if (my_cert) {
						if (verify_cert(certs, my_cert))
							printf("Verified OK\n");
						else 
							printf("Verification fails\n");
						X509_free(my_cert);
					}
					break;
				default:
					printf("Warning: %d extraneous parameter(s)\n", argc - optind);
					usage();
				}
		}
	}

end:
	if (my_domain)
		maemosec_certman_close_domain(my_domain);

	maemosec_certman_close(certs);
	return(0);
}
