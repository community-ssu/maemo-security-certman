/* -*- mode:c; tab-width:4; c-basic-offset:4; -*-
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
 \file cmcli.c
 \ingroup libcertman
 \brief A command-line utility for managing certificate stores

 This command-line utility can be used to list contents of certificate 
 stores, create new stores and manipulate the existing ones by adding
 and deleting certificates in them. It also serves as an example of how
 to use the certman library.
 
*/


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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

static char key_str_buf[MAEMOSEC_KEY_ID_STR_LEN];

extern int inspect_certificate(const char* pathname);

/*
 * Global options
 */
static int force_opt = 0;

/*
 * Utilities. Should maybe be added to libmaemosec_certman0
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

typedef enum {ft_x509_pem, ft_x509_der, ft_x509_sig, ft_pkcs12, ft_unknown} ft_filetype;

static ft_filetype
determine_filetype(FILE* fp, void** idata)
{
	X509* cert;
	PKCS12* cont;
	X509_SIG* ekey;

	*idata = NULL;
	rewind(fp);
	cert = PEM_read_X509(fp, NULL, 0, NULL);
	if (cert) {
		*idata = (void*)cert;
		return(ft_x509_pem);
	} else
		MAEMOSEC_DEBUG(1, "Not a PEM file");

	rewind(fp);
	cert = d2i_X509_fp(fp, NULL);
	if (cert) {
		*idata = (void*)cert;
		return(ft_x509_der);
	} else
		MAEMOSEC_DEBUG(1, "Not a DER file");

	rewind(fp);
	ekey = d2i_PKCS8_fp(fp, NULL);
	if (ekey) {
		*idata = (void*)ekey;
		return(ft_x509_sig);
	} else
		MAEMOSEC_DEBUG(1, "Not a PKCS8 file");

	rewind(fp);
	cont = d2i_PKCS12_fp(fp, NULL);
	if (cont) {
		*idata = (void*)cont;
		return(ft_pkcs12);
	} else
		MAEMOSEC_DEBUG(1, "Not a PKCS12 file");

	return(ft_unknown);
}


static void
print_key_id(maemosec_key_id key_id, char* to_buf, unsigned max_len)
{
	unsigned i;

	if (max_len < 3*MAEMOSEC_KEY_ID_LEN)
		return;
	for (i = 0; i < MAEMOSEC_KEY_ID_LEN; i++) {
		sprintf(to_buf, "%s%02hX", i?":":"", key_id[i]);
		to_buf += strlen(to_buf);
	}
}


static int
decode_key_id(const char* from_buf, maemosec_key_id key_id)
{
	unsigned i = 0;
	unsigned short b;
	const char* f = from_buf;

	if (!from_buf)
		return(0);

	while (*f && sscanf(f, "%02hX", &b)) {
		f += 2;
		if (*f == ':')
			f++;
		key_id[i++] = (unsigned char)b;
		if (i == MAEMOSEC_KEY_ID_LEN)
			break;
	}

	if (i < MAEMOSEC_KEY_ID_LEN) {
		fprintf(stderr, "ERROR: invalid key id '%s'\n", from_buf);
		return(0);
	} else
		return(1);
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
		maemosec_certman_key_id_to_str(key_id, keybuf, sizeof(keybuf));
	else
		strcpy(keybuf, "????????????????????????????????????????");

	if (pos >= 0) 
		printf("%s %s\n", keybuf, name);
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
show_key(int pos, void* key_id, void* ctx)
{
	char keybuf[64];
	maemosec_certman_key_id_to_str(key_id, keybuf, sizeof(keybuf));
	printf("%3d: %s\n", pos, keybuf);
	return(0);
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


void
get_input(char* to_buf, size_t maxlen, int hidden)
{
	int c;
	size_t pos = 0;
	struct termios old_io, new_io;

	/*
	 * Turn off echo
	 */
	if (hidden) {
		ioctl(0, TCGETS, &old_io);
		new_io = old_io;
		new_io.c_lflag &= ~ECHO;
		ioctl(0, TCSETS, &new_io);
	}

	do {
		c = fgetc(stdin);
		switch (c)
			{
			case '\n':
			case '\r':
			case EOF:
				*(to_buf + pos) = '\0';
				goto done;
			case '\b':
				if (pos) {
					pos--;
				} else {
					putchar('\a');
				}
				break;
			default:
				if (pos < maxlen) {
					*(to_buf + pos) = c;
					pos++;
				} else {
					putchar('\a');
				}
				break;
			}
	} while (1);

 done:
	if (hidden)
		ioctl(0, TCSETS, &old_io);
}


static int
install_private_key(X509_SIG* pkey)
{
	printf("%s\n", "Not implemented yet.");
	X509_SIG_free(pkey);
	return(0);
}


static int
show_storage_name(int ordnr, void* data, void* ctx)
{
	printf("\t%s\n", (char*)data);
	return(0);
}


static int
install_pkcs12(PKCS12* cont)
{
	char password[64] = "";
	char storename[64] = "";
	EVP_PKEY *pkey;
	X509 *ucert;
	STACK_OF(X509) *cas = NULL;
	int success, rc;
	domain_handle user_domain, cas_domain;

	success = PKCS12_verify_mac(cont, NULL, 0);
	if (success)
		success = PKCS12_parse(cont, NULL, &pkey, &ucert, &cas);
	else {
		printf("%s\n", "The file is encrypted.");
		do {
			success = PKCS12_verify_mac(cont, password, strlen(password));
			if (0 == success) {
				printf("%s: ", "Give password");
				get_input(password, sizeof(password), 1);
				printf("\n");
			}
		} while (0 == success);
	}

	success = PKCS12_parse(cont, password, &pkey, &ucert, &cas);
	if (0 == success) {
		printf("%s\n", "ERROR: could not parse container. Quit.");
		goto done;
	}

	if (pkey && ucert) {
		maemosec_key_id key_id;
		printf("%s\n", "User certificate and private key detected");
		if (0 == maemosec_certman_get_key_id(ucert, key_id)) {
			printf("%s\n", "Writable certificate stores:");
			maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, 
											 show_storage_name,
											 NULL);
			printf("%s: ", "Give store name for user certificate");
			get_input(storename, sizeof(storename), 0);

			rc = maemosec_certman_open_domain(storename, 
											  MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, 
											  &user_domain);

			if (0 == rc) {
				rc = maemosec_certman_add_cert(user_domain, ucert);
				if (0 == rc)
					printf("Added user certificate to '%s'\n", storename);
				else
					printf("ERROR: could not add user certificate to '%s' (%d)\n", 
						   storename, rc);

				maemosec_certman_close_domain(user_domain);

				rc = maemosec_certman_store_key(key_id, pkey, password);
				if (0 == rc)
					printf("Saved private key\n");
				else
					printf("ERROR: could not save private key (%d)\n", rc);
			}
		}
		X509_free(ucert);
		EVP_PKEY_free(pkey);
	}

	if (cas) {
		printf("%d CA certificates detected\n", sk_X509_num(cas));
		printf("%s\n", "Writable certificate stores:");
		maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, 
										 show_storage_name,
										 NULL);
		printf("%s: ", "Give store name for CA certificates");

		get_input(storename, sizeof(storename), 0);

		rc = maemosec_certman_open_domain(storename, 
										  MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, 
										  &cas_domain);

		if (0 == rc) {
			int i;
			for (i = 0; i < sk_X509_num(cas); i++) {
				X509* cacert = sk_X509_value(cas, i);
				rc = maemosec_certman_add_cert(cas_domain, cacert);
				if (0 == rc)
					printf("Added CA certificate to '%s'\n", storename);
				else
					printf("ERROR: could not add CA certificate to '%s' (%d)\n", 
						   storename, rc);
			}
			maemosec_certman_close_domain(cas_domain);
		}
		sk_X509_free(cas);
	}
	
 done:						  
	PKCS12_free(cont);
	return(0);
}


static int
install_file(const char* filename)
{
	FILE* fp = fopen(filename, "r");
	ft_filetype ft;
	void* idata = NULL;
	int rc = 0;

	if (!fp) {
		fprintf(stderr, "ERROR: cannot open file '%s' (%s)\n",
				filename, strerror(errno));
	}
	ft = determine_filetype(fp, &idata);
	switch (ft) 
		{
		case ft_x509_pem:
		case ft_x509_der:
			fprintf(stderr, "Use -a switch to add certificates\n");
			X509_free((X509*)idata);
			rc = EINVAL;
			break;

		case ft_x509_sig:
			rc = install_private_key((X509_SIG*)idata);
			break;
			
		case ft_pkcs12:
			rc = install_pkcs12((PKCS12*)idata);
			break;
		default:
			rc = EINVAL;
		}
	fclose(fp);
	return(rc);
}


static void
usage(void)
{
	printf(
		"Usage:\n"
		"cmcli [-<T|t> <domain>[:<domain>...]] [-<c|p> <domain>]\n"
		       "-a <cert-file> -i <pkcs12-file> -v <cert-file>\n"
		       "-k <fingerprint> -r <key-id> -b <file>\n" 
		       "[-DL] -d{d}* [-f]\n"
		" -T to load CA certificates from one or more shared domains\n"
		" -t to load CA certificates from one or more private domains\n"
		" -c to open/create a shared domain for modifications\n"
		" -p to open/create a private domain for modifications\n"
		" -a to add a certificate to the given domain\n"
		" -i to install a PKCS#12 container or a single private key\n"
		" -v to verify a certificate against the trusted domains\n"
		" -k to display a private key specified by its fingerprint\n"
		" -r to remove the certificate identified by key id from domain\n"
		" -D to list certificate domains\n"
		" -L to list certificates in the specified domains and all private keys\n"
		" -d, -dd... to increase level of debug info shown\n"
		" -f to force an operation despite warnings\n"
		);
}

typedef enum {cmd_add, cmd_verify, cmd_none} multi_arg_cmd;

/**
 * \brief The main program
 * Execute the command without any parameters to get the help
 */

int
main(int argc, char* argv[])
{
	int rc, i, a, flags;
	domain_handle my_domain = NULL;
	X509_STORE* certs = NULL;
	X509* my_cert = NULL;
	multi_arg_cmd ma_cmd = cmd_none;
	maemosec_key_id my_key_id;

	if (1 == argc) {
		usage();
		return(-1);
	}

	ERR_print_errors_cb(report_openssl_error, NULL);

	rc = maemosec_certman_open(&certs);
	if (rc != 0) {
		fprintf(stderr, "ERROR: cannot open certificate repository (%d)\n", rc);
		return(-1);
	}

    while (1) {
		a = getopt(argc, argv, "T:t:c:p:a:i:v:k:r:DLdfh?A:");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
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

		case 'D':
			printf("Shared domains%s:\n", geteuid()?" (read only)":"");
			maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_SHARED, 
											 show_storage_name,
											 NULL);
			printf("Private domains:\n");
			maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, 
											 show_storage_name,
											 NULL);
			break;

		case 'L':
			printf("Certificates:\n");
			for (i = 0; i < sk_STORE_OBJECT_num(certs->objs); i++) {
				X509_OBJECT* obj = sk_X509_OBJECT_value(certs->objs, i);
				if (obj->type == X509_LU_X509) {
					show_cert(i, obj->data.x509, NULL);
				}
			}
			printf("Private keys:\n");
			maemosec_certman_iterate_keys(show_key, NULL);
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

		case 'A':
			inspect_certificate(optarg);
			break;

		case 'a':
			if (!my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			MAEMOSEC_DEBUG(1, "Adding %d certificates\n", argc - optind + 1);
			for (i = optind - 1; i < argc; i++)
				MAEMOSEC_DEBUG(1, "Add %s\n", argv[i]);
			rc = maemosec_certman_add_certs(my_domain, argv + optind - 1, argc - optind + 1);
			printf("Added %d certificates\n", rc);
			goto end;
			break;

		case 'i':
			install_file(optarg);
			break;

		case 'k':
			if (0 == maemosec_certman_str_to_key_id(optarg, my_key_id)) {
				EVP_PKEY* my_key = NULL;
				char password[64];

				show_key(0, my_key_id, NULL);
				printf("Give password: ");
				get_input(password, sizeof(password), 1);
				printf("\n");
				rc = maemosec_certman_retrieve_key(my_key_id,
												   &my_key,
												   password);
				if (0 == rc) {
					BIO* outfile = BIO_new_fp(stdout, BIO_NOCLOSE);
					if (outfile) {
						rc = PEM_write_bio_PrivateKey(outfile,
													  my_key,
													  NULL,
													  NULL,
													  0,
													  NULL,
													  NULL);
						BIO_free(outfile);
					}
				} else {
					fprintf(stderr, 
							"ERROR: cannot read private key (%d)\n",
							rc);
				}
				if (my_key)
					EVP_PKEY_free(my_key);
			}
			break;

		case 'r':
			if (!my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			if (0 == maemosec_certman_str_to_key_id(optarg, my_key_id)) {
				rc = maemosec_certman_rm_cert(my_domain, my_key_id);
				if (0 != rc) {
					fprintf(stderr, "ERROR: cannot remove certificate (%d)\n", rc);
				}
			} else
				printf("Removed certificate");
			break;

		case 'f':
			force_opt++;
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
