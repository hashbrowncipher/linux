// SPDX-License-Identifier: GPL-2.0
/*
 * Tests x86 MKTME Multi-Key Memory Protection
 *
 * COMPILE w keyutils library ==>  cc -o mktest mktme_test.c -lkeyutils
 *
 * Test requires capability of CAP_SYS_RESOURCE, or CAP_SYS_ADMIN.
 * $ sudo setcap 'CAP_SYS_RESOURCE+ep' mktest
 *
 * Some tests may require root privileges because the test needs to
 * remove the garbage collection delay /proc/sys/kernel/keys/gc_delay
 * while testing. This keeps the tests (and system) from appearing to
 * be out of keys when keys are simply awaiting the next scheduled
 * garbage collection.
 *
 * Documentation/x86/mktme.rst
 *
 * There are examples in here of:
 *  * how to use the Kernel Key Service MKTME API to allocate keys
 *  * how to use the MKTME Memory Encryption API to encrypt memory
 *
 * Adding Tests:
 *	o Each test should run independently and clean up after itself.
 *	o There are no dependencies among tests.
 *	o Tests that use a lot of keys, should consider adding sleep(),
 *	  so that the next test isn't key-starved.
 *	o Make no assumptions about the order in which tests will run.
 *	o There are shared defines that can be used for setting
 *	  payload options.
 */
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <keyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define sys_encrypt_mprotect 335

/*  TODO get this from kernel. Add to /proc/sys/kernel/keys/ */
int max_keyids = 63;

/* Use these pre-defined options to simplify the add_key() setup */
char *options_CPU_short = "algorithm=aes-xts-128 type=cpu";
char *options_CPU_long = "algorithm=aes-xts-128 type=cpu key=12345678912345671234567891234567 tweak=12345678912345671234567891234567";
char *options_USER = "algorithm=aes-xts-128 type=user key=12345678912345671234567891234567 tweak=12345678912345671234567891234567";
char *options_CLEAR = "type=clear";
char *options_NOENCRYPT = "type=no-encrypt";

/* Helper to check Encryption_KeyID in proc/self/smaps */
static FILE *seek_to_smaps_entry(unsigned long addr)
{
	FILE *file;
	char *line = NULL;
	size_t size = 0;
	unsigned long start, end;
	char perms[5];
	unsigned long offset;
	char dev[32];
	unsigned long inode;
	char path[BUFSIZ];

	file = fopen("/proc/self/smaps", "r");
	if (!file) {
		perror("fopen smaps");
		_exit(1);
	}
	while (getline(&line, &size, file) > 0) {
		if (sscanf(line, "%lx-%lx %s %lx %s %lu %s\n",
			   &start, &end, perms, &offset, dev, &inode, path) < 6)
			goto next;

		if (start <= addr && addr < end)
			goto out;
next:
		free(line);
		line = NULL;
		size = 0;
	}
	fclose(file);
	file = NULL;
out:
	free(line);
	return file;
}

/* Find the KeyID for this addr from /proc/self/smaps */
unsigned int find_smaps_keyid(unsigned long addr)
{
	unsigned int keyid = 0;
	char *line = NULL;
	size_t size = 0;
	FILE *smaps;

	smaps = seek_to_smaps_entry(addr);
	if (!smaps) {
		printf("Unable to parse /proc/self/smaps\n");
		goto out;
	}
	while (getline(&line, &size, smaps) > 0) {
		if (!strstr(line, "KeyID:")) {
			free(line);
			line = NULL;
			size = 0;
			continue;
		}
		if (sscanf(line, "KeyID:             %5u\n", &keyid) < 1)
			printf("Unable to parse smaps for KeyID:%s\n", line);
		break;
	}
out:
	free(line);
	fclose(smaps);
	return keyid;
}

/*
 * Set the garbage collection delay to 0, so that keys are quickly
 * available for re-use while running the selftests.
 *
 * Most tests use INVALIDATE to remove a key, which has no delay by
 * design. But, revoke, unlink, and timeout still have a delay, so
 * they should use this.
 */
char current_gc_delay[10] = {0};
static inline int remove_gc_delay(void)
{
	int fd;

	fd = open("/proc/sys/kernel/keys/gc_delay", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("Failed to open /proc/sys/kernel/keys/gc_delay");
		return -1;
	}
	if (read(fd, current_gc_delay, sizeof(current_gc_delay)) <= 0) {
		perror("Failed to read /proc/sys/kernel/keys/gc_delay");
		close(fd);
		return -1;
	}
	lseek(fd, 0, SEEK_SET);
	if (write(fd, "0", sizeof(char)) != sizeof(char)) {
		perror("Failed to write temp_gc_delay to gc_delay\n");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static inline void restore_gc_delay(void)
{
	int fd;

	fd  = open("/proc/sys/kernel/keys/gc_delay", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("Failed to open /proc/sys/kernel/keys/gc_delay");
		return;
	}
	if (write(fd, current_gc_delay, strlen(current_gc_delay)) !=
	    strlen(current_gc_delay)) {
		perror("Failed to restore gc_delay\n");
		close(fd);
		return;
	}
	close(fd);
}

/*
 * The tests are sorted into 3 categories:
 * key_test encrypt_test focus on their specific API
 * flow_tests are special flows and regression tests of prior issue.
 */

#include "key_tests.c"
#include "encrypt_tests.c"
#include "flow_tests.c"

struct tlist {
	const char *name;
	void (*func)();
};

static const struct tlist mktme_tests[] = {
{"Keys: Add each type key",		test_keys_add_each_type		},
{"Flow: One simple roundtrip",		test_one_simple_round_trip	},
{"Keys: Valid Payload Options",		test_keys_valid_options		},
{"Keys: Invalid Payload Options",	test_keys_invalid_options	},
{"Keys: Add Key Descriptor Field",	test_keys_descriptor		},
{"Keys: Add Multiple Same",		test_keys_add_mult_same		},
{"Keys: Change payload, auto update",	test_keys_change_payload	},
{"Keys: Update, explicit update",	test_keys_update_explicit	},
{"Keys: Update, Clear",			test_keys_update_clear		},
{"Keys: Add, Invalidate Keys",		test_keys_add_invalidate	},
{"Keys: Add, Revoke Keys",		test_keys_add_revoke		},
{"Keys: Keyctl Describe",		test_keys_describe		},
{"Keys: Clear",				test_keys_update_clear		},
{"Keys: No Encrypt",			test_keys_no_encrypt		},
{"Keys: Unique KeyIDs",			test_keys_unique_keyid		},
{"Keys: Get Max KeyIDs",		test_keys_get_max_keyids	},
{"Encrypt: Parameter Alignment",	test_param_alignment		},
{"Encrypt: Change Protections",		test_change_protections		},
{"Encrypt: Swap Keys",			test_key_swap			},
{"Encrypt: Counters Same Key",		test_counters_same		},
{"Encrypt: Counters Diff Key",		test_counters_diff		},
{"Encrypt: Counters Holes",		test_counters_holes		},
/*
{"Encrypt: Split",			test_split			},
{"Encrypt: Well Suited",		test_well_suited		},
{"Encrypt: Not Suited",			test_not_suited			},
*/
{"Flow: Switch key no data",		test_switch_key_no_data		},
{"Flow: Switch key multi VMAs",		test_switch_key_mult_vmas	},
{"Flow: Switch No Key to Any Key",	test_switch_key0_to_key		},
{"Flow: madvise",			test_kai_madvise		},
{"Flow: Invalidate In Use Key",		test_discard_in_use_key		},
};

void print_usage(void)
{
	fprintf(stderr, "Usage: mktme_test [options]...\n"
		"  -a			Run ALL tests\n"
		"  -t <testnum>		Run one <testnum> test\n"
		"  -l			List available tests\n"
		"  -h, -?		Show this help\n"
	       );
}

int main(int argc, char *argv[])
{
	int test_selected = -1;
	char printtest[12];
	int trace = 0;
	int i, c, err;
	char *temp;

	/*
	 * TODO: Default case needs to run 'selftests' -  a
	 * curated set of tests that validate functionality but
	 * don't hog resources.
	 */
	c = getopt(argc, argv, "at:lph?");
		switch (c) {
		case 'a':
			test_selected = -1;
			printf("Test Selected [ALL]\n");
			break;
		case 't':
			test_selected = strtoul(optarg, &temp, 10);
			printf("Test Selected [%d]\n", test_selected);
			break;
		case 'l':
			for (i = 0; i < ARRAY_SIZE(mktme_tests); i++)
				printf("[%2d] %s\n", i + 1,
				       mktme_tests[i].name);
			exit(0);
			break;
		case 'p':
			trace = 1;
		case 'h':
		case '?':
		default:
			print_usage();
			exit(0);
		}

/*
 *	if (!cpu_has_mktme()) {
 *		printf("MKTME not supported on this system.\n");
 *		exit(0);
 *	}
 */
	if (trace) {
		printf("Pausing: start trace on PID[%d]\n", (int)getpid());
		getchar();
	}

	if (test_selected == -1) {
		for (i = 0; i < ARRAY_SIZE(mktme_tests); i++) {
			printf("[%2d] %s\n", i + 1, mktme_tests[i].name);
			mktme_tests[i].func();
		}
		printf("\nTests Completed\n");

	} else {
		if (test_selected <= ARRAY_SIZE(mktme_tests)) {
			printf("[%2d] %s\n", test_selected,
			       mktme_tests[test_selected - 1].name);
			mktme_tests[test_selected - 1].func();
			printf("\nTest Completed\n");
		}
	}
	exit(0);
}
