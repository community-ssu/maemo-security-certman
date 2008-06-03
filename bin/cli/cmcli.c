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

#include <libcertman.h>

extern int debug_level;

/**
 * \brief How to verify a certificata against a store
 * \param store A certificate store, for instance one created
 * by ngcm_open+ngcm_collect
 * \param cert The ceritificate to be verified
 * \returns 1 on success, 0 on failure
 */

int
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
	X509_STORE_CTX_free(csc);

	return(retval);
}


static void
usage(void)
{
	printf(
		"Usage:\n"
		"cmcli [-v <domain>[:<domain>...]] [-<c|p> <domain>] -a <cert-file>\n"
		"       -i <cert-file> -r <num> [-D*]\n"
		" -v to load certificates from given common domains for verification\n"
		" -c to open/create a common domain for modifications\n"
		" -p to open/create a private domain for modifications\n"
		" -l to list certificates in the given domain (both -v and -d)\n"
		" -a to add a certificate to the given domain\n"
		" -i to show certificate information of the given certificate\n"
		" -r to remove the nth certificate from the given domain\n"
		" -D, -DD... to increase level of debug info shown\n"
		);
}


static int
show_cert(int pos, X509* cert)
{
	char buf[255], *name;

	if (!cert)
		return(ENOENT);

	name = X509_NAME_oneline(X509_get_subject_name(cert),
							 buf, 
							 sizeof(buf));
				
	printf("%2d: %s\n", pos, name);
	return(0);
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


int
main(int argc, char* argv[])
{
	int rc, i, a, flags, my_domain = -1;
	X509_STORE* certs = NULL;
	X509* my_cert = NULL;
	struct certman_cmd* commands = NULL;

	rc = ngsw_certman_open(&certs);
	if (rc != 0) {
		fprintf(stderr, "ERROR: cannot open certificate repository (%d)\n", rc);
		return(-1);
	}

    while (1) {
		a = getopt(argc, argv, "v:c:p:a:Dl");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
		case 'D':
			debug_level++;
			break;

		case 'v':
			rc = ngsw_certman_collect(optarg, certs);
			if (rc != 0) {
				fprintf(stderr, "ERROR: cannot open domain '%s' (%d)\n", 
						optarg, rc);
				return(-1);
			}
			break;

		case 'c':
		case 'p':
			if ('c' == a)
				flags = NGSW_CD_COMMON;
			else
				flags = NGSW_CD_PRIVATE;
			rc = ngsw_certman_open_domain(optarg, flags, &my_domain);
			if (0 != rc) {
				fprintf(stderr, "ERROR: cannot open/create domain '%s' (%d)\n", 
						optarg, rc);
				return(-1);
			}
			break;

		case 'a':
		case 'e':
			if (-1 == my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			my_cert = get_cert(optarg);
			if (my_cert) {
				char buf[255], *name;

				name = X509_NAME_oneline(X509_get_subject_name(my_cert),
										 buf, 
										 sizeof(buf));
				
				if (a == 'a') {
					rc = ngsw_certman_add_cert(my_domain, my_cert);
					if (0 == rc)
						printf("%s\nAdded\n", name);
					else
						fprintf(stderr, "ERROR: cannot add 's' (%d)\n",
								name, rc);
				} else if (a == 'e') {
					rc = ngsw_certman_rm_cert(my_domain, my_cert);
					if (0 == rc)
						printf("%s\nAdded\n", name);
					else
						fprintf(stderr, "ERROR: cannot add 's' (%d)\n",
								name, rc);
				}
				X509_free(my_cert);
			}
			break;

		case 'I':
			if (-1 == my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			rc = ngsw_certman_iterate_domain(my_domain, show_cert);
			if (0 != rc) {
				fprintf(stderr, "ERROR: cannot iterate domain (%d)\n", rc);
			}
			break;

		case 'i':
			my_cert = get_cert(optarg);
			if (my_cert) {
				char buf[255], *name;

				name = X509_NAME_oneline(X509_get_subject_name(my_cert),
										 buf, 
										 sizeof(buf));

				if (ngsw_cert_is_valid(certs, my_cert))
					printf("%s\nVerified\n", name);
				else 
					printf("%s\nVerification fails\n", name);
				
				X509_free(my_cert);

			}
			break;

		case 'l':
			// sk_STORE_OBJECT_num is not defined in the scratchbox
			// version of OpenSSL, so define it here
#ifndef sk_STORE_OBJECT_num
#define sk_STORE_OBJECT_num(st) SKM_sk_num(STORE_OBJECT, (st))
#endif
			for (i = 0; i < sk_STORE_OBJECT_num(certs->objs); i++) {
				X509_OBJECT* obj = sk_X509_OBJECT_value(certs->objs, i);
				if (obj->type == X509_LU_X509) {
					char buf[255];
					char* name;
					name = X509_NAME_oneline(X509_get_subject_name(obj->data.x509),
											 buf, 
											 sizeof(buf));
					printf("\t%d:%s\n", i, buf);
				}
			}
			break;

		default:
			usage();
			return(0);
		}
	}

	if (-1 != my_domain)
		ngsw_certman_close_domain(my_domain);

	ngsw_certman_close(certs);
	return(0);
}
