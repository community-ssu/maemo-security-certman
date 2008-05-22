/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include <sec_common.h>
#include <sec_storage.h>
using namespace ngsw_sec;

extern int debug_level;

static void 
usage(void)
{
	printf(
		"Usage: sscli -s <storage> -c<s|e> -a|d|v <filename>\n"
		" -s to give the storage name (must be first argument)\n"
		" -c to create a new storage, \"s\" for signed and \"e\" for encrypted\n" 
		" -a to add/update a file to the storage\n"
		" -d to remove a file from the storage\n"
		" -v to verify the file contents\n"
		" -x to decrypt an encrypted file and print it to stdout\n"
		" -e to read from stdin and update and encrypted file\n"
		);
}

int
main(int argc, char* argv[])
{
	char a;
	char* storagename = NULL;
	storage* ss = NULL;

    while (1) {
		a = getopt(argc, argv, "s:c:a:d:x:e:v::D");
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
			return(0);
			break;

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

		case 'x':
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
				int handle;
				ss->get_file(optarg, &handle, &buf, &len);
				for (ssize_t i = 0; i < len; i++) {
					putchar(*(buf + i));
				}
				ss->close_file(handle, &buf, len);
			}
			break;

		case 'e':
			ERROR("not implemented yet");
			return(-1);
		   
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

	return(0);
}

	

