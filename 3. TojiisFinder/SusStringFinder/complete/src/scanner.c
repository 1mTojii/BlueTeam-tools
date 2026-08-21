#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "scanner.h"

void matchlist_init(MatchList *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void matchlist_free(MatchList *list) {
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void matchlist_add(MatchList *list, long offset, const Signature *sig, const char *context) {
    if (list->count == list->capacity) {
        int new_capacity = (list->capacity == 0) ? 8 : list->capacity * 2;
        Match *bigger = realloc(list->items, (size_t)new_capacity * sizeof(Match));
        if (!bigger) {
            /* Allocation failed -- silently drop the match rather than
             * crash. Not ideal, but acceptable for a triage tool. */
            return;
        }
        list->items = bigger;
        list->capacity = new_capacity;
    }

    Match *m = &list->items[list->count];
    m->offset = offset;
    m->sig = sig;

    /* context is always produced by extract_context() at <= CONTEXT_LEN
     * bytes plus its own null terminator, so a plain bounded copy is
     * sufficient here -- using memcpy (rather than strncpy) also avoids
     * a spurious truncation warning some compilers raise at -O2. */
    size_t len = strlen(context);
    if (len > CONTEXT_LEN) {
        len = CONTEXT_LEN;
    }
    memcpy(m->context, context, len);
    m->context[len] = '\0';

    list->count++;
}

/* Grabs a small printable snippet of the buffer around a match, for
 * displaying "here's what the suspicious line actually looked like".
 * Non-printable bytes (control characters, raw binary) are replaced with
 * '.' so the terminal output doesn't get garbled or do anything weird. */
static void extract_context(const char *buffer, long size, long match_pos,
                             size_t match_len, char *out, size_t out_cap) {
    long context_start = match_pos - 15;
    if (context_start < 0) context_start = 0;

    long context_end = match_pos + (long)match_len + 30;
    if (context_end > size) context_end = size;

    size_t out_i = 0;
    for (long i = context_start; i < context_end && out_i < out_cap - 1; i++) {
        unsigned char c = (unsigned char)buffer[i];
        out[out_i++] = isprint(c) ? (char)c : '.';
    }
    out[out_i] = '\0';
}

void scan_buffer(const char *buffer, long size, MatchList *out) {
    for (int s = 0; s < SIGNATURE_COUNT; s++) {
        const Signature *sig = &SIGNATURES[s];
        size_t needle_len = strlen(sig->pattern);

        if (needle_len == 0 || (long)needle_len > size) {
            continue;
        }

        for (long i = 0; i + (long)needle_len <= size; i++) {
            int matched = 1;
            for (size_t j = 0; j < needle_len; j++) {
                if (tolower((unsigned char)buffer[i + j]) != tolower((unsigned char)sig->pattern[j])) {
                    matched = 0;
                    break;
                }
            }

            if (matched) {
                char context[CONTEXT_LEN + 1];
                extract_context(buffer, size, i, needle_len, context, sizeof(context));
                matchlist_add(out, i, sig, context);
            }
        }
    }
}

int scan_file(const char *filepath, MatchList *out) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);

    if (size == 0) {
        fclose(f);
        return 0;  /* empty file, nothing to scan, not an error */
    }

    char *buffer = malloc((size_t)size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)size, f);
    fclose(f);

    if (bytes_read != (size_t)size) {
        /* Short read -- something went wrong partway through. Bail rather
         * than scan a partially-garbage buffer. */
        free(buffer);
        return -1;
    }

    scan_buffer(buffer, size, out);
    free(buffer);
    return 0;
}
