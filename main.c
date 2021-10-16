#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int init_main(int, char **, char *);
int genkey_main(int, char **, char *);
int pubkey_main(int, char **, char *);
int backup_main(int, char **, char *);
int commit_main(int, char **, char *);
int abort_main(int, char **, char *);
int restore_main(int, char **, char *);
int prune_main(int, char **, char *);

static void usage(char *progname)
{
	printf("usage: %s [-C <dir>] <command> [args]\n", progname);
}

int main(int argc, char **argv)
{
	int c;
	char *progname = argv[0];

	while ((c=getopt(argc, argv, "+C:")) >= 0) switch (c) {
	case 'C':
		chdir(optarg);
		break;
	case '?':
		usage(progname);
		return 1;
	}

	argc-=optind;
	argv+=optind;
	optind = 1;
	char *cmd = argv[0];

	if (!cmd) {
		usage(progname);
		return 0;
	} else if (!strcmp(cmd, "init")) {
		return init_main(argc, argv, progname);
	} else if (!strcmp(cmd, "genkey")) {
		return genkey_main(argc, argv, progname);
	} else if (!strcmp(cmd, "pubkey")) {
		return pubkey_main(argc, argv, progname);
	} else if (!strcmp(cmd, "backup")) {
		return backup_main(argc, argv, progname);
	} else if (!strcmp(cmd, "commit")) {
		return commit_main(argc, argv, progname);
	} else if (!strcmp(cmd, "abort")) {
		return abort_main(argc, argv, progname);
	} else if (!strcmp(cmd, "restore")) {
		return restore_main(argc, argv, progname);
	} else if (!strcmp(cmd, "prune")) {
		return prune_main(argc, argv, progname);
	} else {
		printf("unknown command: %s\n", cmd);
		usage(progname);
		return 1;
	}
}
