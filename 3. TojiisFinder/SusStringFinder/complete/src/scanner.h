#ifndef SCANNER_H
#define SCANNER_H

#include "signatures.h"

#define CONTEXT_LEN 60

typedef struct {
    long offset;              /* byte offset in the file where the match starts */
    const Signature *sig;     /* which signature matched */
    char context[CONTEXT_LEN + 1];
} Match;

typedef struct {
    Match *items;
    int count;
    int capacity;
} MatchList;

void matchlist_init(MatchList *list);
void matchlist_free(MatchList *list);

/* Scans an in-memory buffer against all known signatures, appending any
 * hits to `out`. */
void scan_buffer(const char *buffer, long size, MatchList *out);

/* Reads a file fully into memory and scans it. Returns 0 on success,
 * -1 on failure (file couldn't be opened/read). */
int scan_file(const char *filepath, MatchList *out);

#endif
