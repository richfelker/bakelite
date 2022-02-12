#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct snapinfo {
	const char *name;
	struct timespec ts;
	int has_bloom;
	int keep;
};

static int is_later_than(const struct timespec *ts, const struct timespec *ts0)
{
	if (ts->tv_sec < ts0->tv_sec) return 0;
	if (ts->tv_sec > ts0->tv_sec || ts->tv_nsec > ts0->tv_nsec) return 1;
	return 0;
}

static void keep_latest_before(struct snapinfo *snaps, int nsnaps, const struct timespec *ts)
{
	int l = -1;
	for (int i=0; i<nsnaps; i++) {
		if (!snaps[i].has_bloom) continue;
		if (is_later_than(&snaps[i].ts, ts)) continue;
		if (l<0 || is_later_than(&snaps[i].ts, &snaps[l].ts))
			l = i;
	}
	if (l>=0) snaps[l].keep = 1;
}

static void usage(char *progname)
{
	printf("usage: %s cull [options] <summary_file> ...\n", progname);
}

int cull_main(int argc, char **argv, char *progname)
{
	int c;
	int list_keeps = 0;
	int days=0, weeks=0, months=0, years=0, all_range=86400;

	while ((c=getopt(argc, argv, "d:w:m:y:v")) >= 0) switch (c) {
	case 'r':
		all_range = strtol(optarg, 0, 10);
		break;
	case 'd':
		days = strtol(optarg, 0, 10);
		break;
	case 'w':
		weeks = strtol(optarg, 0, 10);
		break;
	case 'm':
		months = strtol(optarg, 0, 10);
		break;
	case 'y':
		years = strtol(optarg, 0, 10);
		break;
	case 'v':
		list_keeps = 1;
		break;
	case '?':
		usage(progname);
		return 1;
	}

	int nsnaps = argc-optind;
	if (!nsnaps) return 1;
	struct snapinfo *snaps = calloc(nsnaps, sizeof *snaps);
	if (!snaps) return 1;

	for (int i=0; i<nsnaps; i++) {
		// missing: first check sig
		snaps[i].name = argv[i+optind];
		FILE *f = fopen(snaps[i].name, "rbe");
		char buf[256];
		while (fgets(buf, sizeof buf, f)) {
			if (!strncmp(buf, "timestamp ", 10)) {
				long long sec;
				long nsec;
				sscanf(buf+10, "%lld.%9ld", &sec, &nsec);
				snaps[i].ts.tv_sec = sec;
				snaps[i].ts.tv_nsec = nsec;
			}
			if (!strncmp(buf, "bloom ", 6)) {
				snaps[i].has_bloom = 1;
			}
		}
		fclose(f);
	}
	struct timespec ts_last = snaps[0].ts;
	for (int i=1; i<nsnaps; i++) {
		if (is_later_than(&snaps[i].ts, &ts_last))
			ts_last = snaps[i].ts;
	}
	struct timespec ts_ref;

	// keep everything within past all_range
	ts_ref = ts_last;
	ts_ref.tv_sec -= all_range;
	for (int i=0; i<nsnaps; i++)
		if (is_later_than(&snaps[i].ts, &ts_ref) && snaps[i].has_bloom)
			snaps[i].keep = 1;

	struct tm tm;

	// last n days
	gmtime_r(&ts_last.tv_sec, &tm);
	tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
	for (int j=0; j<days; j++) {
		ts_ref.tv_sec = timegm(&tm);
		ts_ref.tv_nsec = 0;
		keep_latest_before(snaps, nsnaps, &ts_ref);
		tm.tm_mday--;
	}

	// last n weeks
	gmtime_r(&ts_last.tv_sec, &tm);
	tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
	tm.tm_mday -= tm.tm_wday;
	for (int j=0; j<weeks; j++) {
		ts_ref.tv_sec = timegm(&tm);
		ts_ref.tv_nsec = 0;
		keep_latest_before(snaps, nsnaps, &ts_ref);
		tm.tm_mday -= 7;
	}

	//last n months
	gmtime_r(&ts_last.tv_sec, &tm);
	tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
	tm.tm_mday = 1;
	for (int j=0; j<months; j++) {
		ts_ref.tv_sec = timegm(&tm);
		ts_ref.tv_nsec = 0;
		keep_latest_before(snaps, nsnaps, &ts_ref);
		tm.tm_mon--;
	}

	//last n years
	gmtime_r(&ts_last.tv_sec, &tm);
	tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
	tm.tm_mday = 1;
	tm.tm_mon = 0;
	for (int j=0; j<years; j++) {
		ts_ref.tv_sec = timegm(&tm);
		ts_ref.tv_nsec = 0;
		keep_latest_before(snaps, nsnaps, &ts_ref);
		tm.tm_year--;
	}

	for (int i=0; i<nsnaps; i++)
		if (!!snaps[i].keep == !!list_keeps) puts(snaps[i].name);
	return 0;
}
