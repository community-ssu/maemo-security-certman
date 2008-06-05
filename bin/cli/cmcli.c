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

static void
usage(void)
{
	printf(
		"Usage:\n"
		"cmcli [-t <domain>[:<domain>...]] [-<c|p> <domain>] -a <cert-file>\n"
		"       -v <cert-file> -r <num> [-D*] [-L]\n"
		" -T to specify shared domains of trusted signing certificates\n"
		" -t to specify private domains of trusted signing certificates\n"
		" -v to verify a certificate against the trusted domains\n"
		" -c to open/create a shared domain for modifications\n"
		" -p to open/create a private domain for modifications\n"
		" -a to add a certificate to the given domain\n"
		" -r to remove the nth certificate from the given domain\n"
		" -L to list all certificates\n"
		" -D, -DD... to increase level of debug info shown\n"
		);
}


static int
show_cert(int pos, X509* cert, void* x)
{
	char buf[255], *name;
	int i;

	if (!cert)
		return(ENOENT);

	name = X509_NAME_oneline(X509_get_subject_name(cert),
							 buf, 
							 sizeof(buf));

	if (pos >= 0) 
		printf("%d: %s\n", pos, name);
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


int
main(int argc, char* argv[])
{
	int rc, i, a, pos, flags;
	int my_domain = -1;
	X509_STORE* certs = NULL;
	X509* my_cert = NULL;

	rc = ngsw_certman_open(&certs);
	if (rc != 0) {
		fprintf(stderr, "ERROR: cannot open certificate repository (%d)\n", rc);
		return(-1);
	}

    while (1) {
		a = getopt(argc, argv, "t:T:c:p:a:v:r:DL");
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
			rc = ngsw_certman_collect(optarg, ('T' == a), certs);
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
			break;

		case 'L':
			// sk_STORE_OBJECT_num is not defined in the scratchbox
			// version of OpenSSL, so define it here
#ifndef sk_STORE_OBJECT_num
#define sk_STORE_OBJECT_num(st) SKM_sk_num(STORE_OBJECT, (st))
#endif
			printf("Trusted:\n");
			for (i = 0; i < sk_STORE_OBJECT_num(certs->objs); i++) {
				X509_OBJECT* obj = sk_X509_OBJECT_value(certs->objs, i);
				if (obj->type == X509_LU_X509) {
					show_cert(i, obj->data.x509, NULL);
				}
			}
			// Also list domain contents, if one is opened
			if (-1 != my_domain) {
				printf("Private:\n");
				ngsw_certman_iterate_domain(my_domain, show_cert, NULL);
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
				
				rc = ngsw_certman_add_cert(my_domain, my_cert);
				if (0 == rc)
					printf("%s\nAdded\n", name);
				else
					fprintf(stderr, "ERROR: cannot add '%s' (%d)\n",
							name, rc);

				X509_free(my_cert);
			}
			break;

		case 'r':
			if (-1 == my_domain) {
				fprintf(stderr, "ERROR: must specify domain first\n");
				return(-1);
			}
			pos = atoi(optarg);
			if (pos < 0 || pos >= ngsw_certman_nbrof_certs(my_domain)) {
				fprintf(stderr, 
						"ERROR: domain does not contain certificate #%d\n",
						pos);
				goto end;
				
			}
			rc = ngsw_certman_rm_cert(my_domain, pos);
			if (0 != rc) {
				fprintf(stderr, "ERROR: cannot remove certificate #%d (%d)\n",
							pos, rc);
			}
			break;

		default:
			usage();
			return(0);
		}
	}

end:
	if (-1 != my_domain)
		ngsw_certman_close_domain(my_domain);

	ngsw_certman_close(certs);
	return(0);
}
