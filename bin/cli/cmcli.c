/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/pem.h>

#include <libcertman.h>

extern int debug_level;

int
verify_cert(X509_STORE* ctx, X509* cert)
{
	X509_STORE_CTX *csc;
	int retval;
	int rc;

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		fprintf(stderr, "ERROR: cannot create new context\n");
		return(0);
	}

	rc = X509_STORE_CTX_init(csc, ctx, cert, NULL);
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
		"Usage: cmcli -d <domain> -v <cert>\n"
		" -d to open the certificates of \"domain\"\n"
		" -v to verify the given certificate\n"
		);
}

int
main(int argc, char* argv[])
{
	int rc, i;
	char a;
	X509_STORE* certs = NULL;
	X509* my_cert = NULL;
	FILE* fp;

	rc = ngcm_open(&certs);
	if (rc != 0) {
		fprintf(stderr, "ERROR: cannot open ngcm (%d)\n", rc);
		return(-1);
	}

    while (1) {
		a = getopt(argc, argv, "v:d:Dl");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
		case 'D':
			debug_level++;
			break;

		case 'd':
			rc = ngcm_collect(optarg, certs);
			if (rc != 0) {
				fprintf(stderr, "ERROR: cannot open domain '%s' (%d)\n", 
						optarg, rc);
				return(-1);
			}
			break;

		case 'v':
			fp = fopen(optarg, "r");
			if (!fp) {
				fprintf(stderr, "Cannot read '%s' (%d)\n", optarg, errno);
				return(0);
			}
			my_cert = PEM_read_X509(fp, NULL, 0, NULL);
			if (!my_cert) {
				fprintf(stderr, "Cannot read certificate from '%s'\n", 
						optarg);
			}
			fclose(fp);
			break;

		case 'l':
			// This doesn't work with older version of openssl, 
			// as the sk_STORE_OBJECT_num is missing?
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

	if (my_cert) {
		char buf[255], *name;

		name = X509_NAME_oneline(X509_get_subject_name(my_cert),
								 buf, 
								 sizeof(buf));

		if (verify_cert(certs, my_cert)) {
			printf("%s\nVerified\n", name);

		} else {
			printf("%s\nVerification fails\n", name);
		}
		X509_free(my_cert);
	}

	ngcm_close(certs);
	return(0);
}
