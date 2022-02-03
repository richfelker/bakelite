#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include "match.h"

struct matcher {
	regex_t re;
};

void pat2ere(FILE *f, const char *s)
{
	size_t i, j;
	char *z = strchr(s, '/');
	if (!z || !z[1]) {
		// If no / or just final / to force directory-only matches,
		// match in any directory (same as "**/" prefix).
		fputs("/(.*/)?", f);
	} else if (s[0]!='/') {
		putc('/', f);
	}
	for (i=0; s[i]; i++) {
		switch (s[i]) {
		case '\\':
			switch(s[++i]) {
			case 0:
				fputs("\\\\", f);
				return;
			case '*':
			case '[':
			case '?':
				putc('\\', f);
			default:
				putc(s[i], f);
			}
			break;
		case '/':
			putc('/', f);
			if (s[i+1]!='*' || s[i+2]!='*')
				break;
			i++;
		case '*':
			if (s[i+1]=='*' && (!s[i+2] || s[i+2]=='/') && (!i || s[i-1]=='/')) {
				if (!i) putc('/', f);
				fputs("(.*", f);
				if (s[i+2]) {
					fputs("/)?", f);
					i++;
				} else {
					fputs(")?.", f);
				}
				i++;
			} else {
				fputs("[^/]*", f);
			}
			break;
		case '?':
			fputs("[^/]", f);
			break;
		case '[':
			j=i+1;
			if (s[j]=='^' || s[j]=='!') j++;
			if (s[j]==']') j++;
			for (; s[j] && s[j]!=']'; j++) {
				if (s[j]=='[' && (s[j+1]==':' || s[j+1]=='.' || s[j+1]=='=')) {
					int c = s[++j];
					while (s[j+1] && s[j+2] && (s[j+1]!=c || s[j+2]!=']')) j++;
				}
			}
			if (s[j]) {
				putc('[', f);
				if (s[i+1]=='!') putc('^', f);
				else putc(s[i+1], f);
				for (i=i+2; i<j; i++)
					putc(s[i], f);
				putc(']', f);
				break;
			}
		case '.':
		case '(':
		case '+':
		case '{':
		case '|':
		case '^':
		case '$':
			putc('\\', f);
		default:
			putc(s[i], f);
			break;
		}
	}
}

struct matcher *matcher_from_file(FILE *f)
{
	struct matcher *m = calloc(1, sizeof *m);
	if (!m) return 0;

	char *re_buf;
	size_t re_len;
	FILE *re_f = open_memstream(&re_buf, &re_len);

	char *in_buf = 0;
	size_t in_len = 0;
	int first = 1;
	ssize_t l;
	while ((l=getline(&in_buf, &in_len, f)) > 0) {
		if (in_buf[l-1]=='\n') {
			in_buf[--l] = 0;
		}
		if (!l) continue;
		if (first) {
			fputs("^(", re_f);
			first = 0;
		} else {
			putc('|', re_f);
		}
		pat2ere(re_f, in_buf);
		// Directory names for matching will be passed with a final
		// slash. Adding "/?" to end of regex allows patterns not
		// ending in / to match either file or directory.
		fputs("/?", re_f);
	}
	if (first) {
		// If there were no patterns, 
		fputs("$ ^", re_f);
	} else {
		fputs(")$", re_f);
	}
	fflush(re_f);
	if (ferror(f) || ferror(re_f)) {
		fclose(re_f);
		return 0;
	}
	fclose(re_f);

//fprintf(stderr, "%s\n", re_buf);
	if (regcomp(&m->re, re_buf, REG_EXTENDED|REG_NOSUB)) {
		return 0;
	}
	return m;
}

int matcher_matches(struct matcher *m, const char *s)
{
	if (!m) return 0;
	int r = regexec(&m->re, s, 0, 0, 0);
	if (r==REG_OK) return 1;
	if (r==REG_NOMATCH) return 0;
	return -1;
}

#if 0
int main()
{
	matcher_from_file(stdin);
}
#endif
