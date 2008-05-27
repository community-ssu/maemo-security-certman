/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include <sec_common.h>
#include <sec_storage.h>
#include <libbb5stub.h>

using namespace ngsw_sec;

extern int debug_level;

static void 
usage(void)
{
	printf(
		"Usage: sscli -s <storage> -c<s|e> -a|d|v <filename>\n"
		" -s to give the storage name (must be first argument)\n"
		" -c to create a new storage, \"s\" for signed and \"e\" for encrypted\n" 
		" -a to add a file to the storage\n"
		" -u to update a file in the storage.\n"
		"       With an encrypted storage the new contents is read from stdin\n"
		" -d to remove a file from the storage\n"
		" -v to verify the file contents\n"
		" -p to print the file contents to stdout\n"
		);
}

int
main(int argc, char* argv[])
{
	char a;
	char* storagename = NULL;
	storage* ss = NULL;
	int len;
	X509_STORE* certs;

	certs = bb5_init();

    while (1) {
		a = getopt(argc, argv, "s:c:a:d:p:u:r:v::D");
		if (a < 0) {
			break;
		}
		switch(a) 
		{
		case 'D':
			debug_level++;
			break;

		case 's':
			storagename = optarg;
			break;

		case 'c':
			if (!storagename) {
				ERROR("must give storage name first");
				return(-1);
			}
			if (*optarg == 'e') {
				ss = new storage(storagename, storage::prot_encrypt);
			} else if (*optarg == 's') {
				ss = new storage(storagename, storage::prot_sign);
			} else
				ERROR("Invalid protection mode");
			break;

		case 'a':
			if (!ss) {
				if (!storagename) {
					ERROR("create storage first");
					return(-1);
				} else
					ss = new storage(storagename);
			}
			ss->add_file(optarg);
			break;

		case 'v':
			if (!ss) {
				if (!storagename) {
					ERROR("create storage first");
					return(-1);
				} else
					ss = new storage(storagename);
			}
			if (optarg) {
				if (ss->verify_file(optarg)) {
					printf("Verify OK\n");
				} else {
					printf("Verification fails\n");
				}
			} else {
				storage::stringlist files;
				ss->get_files(files);
				for (size_t i = 0; i < files.size(); i++) {
					printf("%s: ", files[i]);
					if (ss->verify_file(files[i]))
						printf("OK\n");
					else
						printf("FAILED\n");
				}
			}
			delete(ss);
			ss = NULL;
			goto end;

		case 'd':
			if (!ss) {
				if (!storagename) {
					ERROR("create storage first");
					return(-1);
				} else
					ss = new storage(storagename);
			}
			ss->remove_file(optarg);
			break;

		case 'p':
			if (!ss) {
				if (!storagename) {
					ERROR("create storage first");
					return(-1);
				} else
					ss = new storage(storagename);
			}
			{
				unsigned char* buf;
				ssize_t len;
				int handle, rc;
				
				rc = ss->get_file(optarg, &handle, &buf, &len);
				if (0 == rc) {
					for (ssize_t i = 0; i < len; i++) {
						putchar(*(buf + i));
					}
				} else {
					ERROR("failed to open file (%d)", rc);
				}
				ss->close_file(handle, &buf, len);
			}
			break;

		case 'u':
			if (!ss) {
				if (!storagename) {
					ERROR("create storage first");
					return(-1);
				} else
					ss = new storage(storagename);
			}
			{
				int rc, c;
				unsigned char* buf;
				ssize_t len = 0, blen = 1024;

				buf = (unsigned char*)malloc(blen);
				if (!buf) {
					ERROR("cannot malloc");
					return(-1);
				}
				do {
					c = getchar();
					if (c >= 0) {
						if (len == blen) {
							unsigned char* swp;

							blen *= 2;
							swp = (unsigned char*)malloc(blen);
							if (!swp) {
								ERROR("cannot malloc %d", blen);
								return(-1);
							}
							memcpy(swp, buf, len);
							free(buf);
							buf = swp;
						}
						buf[len++] = (unsigned char)c;
					} else
						break;
				} while (true);

				rc = ss->put_file(optarg, buf, len);
				if (rc != 0) {
					ERROR("cannot update '%s' (%d)", optarg, rc);
				}
				free(buf);
			}
			break;

		case 'r':
			len = atoi(optarg);
			if (len > 0) {
				unsigned char* rdata = (unsigned char*) malloc(len);
				if (rdata) {
					bb5_get_random(rdata, len);
					for (int i = 0; i < len; i++)
						printf("%02x", rdata[i]);
					printf("\n");
					free(rdata);
				} else
					ERROR("cannot malloc");
			}
			goto end;
		   
		default:
			usage();
			return(-1);
		}
	}

	if (ss) {
		ss->commit();
		delete(ss);
	} else
		usage();

  end:
	X509_STORE_free(certs);
	bb5_finish();

	return(0);
}

	

