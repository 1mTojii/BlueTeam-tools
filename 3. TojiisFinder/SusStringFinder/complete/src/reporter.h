#ifndef REPORTER_H
#define REPORTER_H

#include "scanner.h"

void print_banner(void);
void print_file_header(const char *filepath);
void print_match(const Match *m);
void print_summary(int scanned, int flagged, int matches);

#endif
