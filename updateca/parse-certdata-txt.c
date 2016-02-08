/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

const char infilename[] = "certdata.txt";
static char ibuf[512];
static unsigned char valbuf[4096];
static size_t vallen;
char g_outfilename[255];

static enum {
    in_value,
    out_value
} read_status = out_value;

static void
write_cert(X509* cert)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    char outfilename[128] = "./certs/", *to;

/*
    if ( X509_pubkey_digest(cert, EVP_sha1(), digest, NULL)) {
*/
	if (X509_digest(cert, EVP_sha1(), digest, NULL)) {
        FILE* outfile;
        int i;
        to = outfilename + strlen(outfilename);
        for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf(to, "%02x", digest[i]);
            to += 2;
        }
        strcat(to, ".pem");
        outfile = fopen(outfilename, "a");
        if (outfile) {
            printf("%s ", outfilename);
            PEM_write_X509(outfile, cert);
            fclose(outfile);
			strcpy(g_outfilename, outfilename);
        }
    }
}

#define sa(s) s,strlen(s)				

int main(void)
{
    FILE* infile = fopen(infilename, "r");
    char* to;
    unsigned cnt = 0, trusted = 0;

    if (!infile) {
        fprintf(stderr, "Cannot open '%s' (%s)\n", infilename, strerror(errno));
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    while (fgets(ibuf, sizeof(ibuf), infile)) {
        if (out_value == read_status) {
            if (0 == strcmp("CKA_VALUE MULTILINE_OCTAL\n", ibuf)) {
                cnt++;
                read_status = in_value;
                to = valbuf;
                vallen = 0;
            } else if (0 == memcmp(ibuf, sa("CKA_TRUST"))) {
                if (0 == strlen(g_outfilename))
                    continue;
                printf("%s", ibuf);
				if (strstr(ibuf, "CKT_NSS_NOT_TRUSTED")) {
					if (strlen(g_outfilename) && 0 == access(g_outfilename, F_OK)) {
						char not_trusted_filename[255], *tmp;
						strcpy(not_trusted_filename, g_outfilename);
						tmp = strstr(not_trusted_filename, ".pem");
						if (tmp) {
							strcpy(tmp, ".untrusted");
							printf("\t -> %s\n", not_trusted_filename);
							if (0 > rename(g_outfilename, not_trusted_filename))
								fprintf(stderr, "ERROR: cannot rename '%s'"
										" to %s' (%s)", g_outfilename, 
										not_trusted_filename,
										strerror(errno));
						} else {
							printf("%s, remove\n", g_outfilename);
							unlink(g_outfilename);
						}
					}
                }
                g_outfilename[0] = '\0';
			}
        } else if (in_value == read_status) {
            if (0 == strcmp("END\n", ibuf)) {
                const unsigned char* bp = valbuf;
                X509* cert = d2i_X509(NULL, &bp, vallen);
                if (cert) {
                    printf("%3d: ", cnt);
                    write_cert(cert);
                    X509_free(cert);
                } else
                    printf("%3d: ERROR\n", cnt);
                read_status = out_value;
            } else {
                char* inp = ibuf;
                while (*inp && '\n' != *inp) {
                    short unsigned int b;
                    if (sscanf(inp, "\\%3ho", &b)) {
                        *to++ = (char)b;
                        vallen++;
                    }
                    inp += 4;
                }
            }
        }
    }
    fclose(infile);

    // RAND_cleanup();
    EVP_cleanup();
    X509_TRUST_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();

    return(0);
}
