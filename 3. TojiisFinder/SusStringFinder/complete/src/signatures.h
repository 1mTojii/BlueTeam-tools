#ifndef SIGNATURES_H
#define SIGNATURES_H

/*
 * Signature list for SusStringFinder.
 */

typedef enum {
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} Severity;

typedef struct {
    const char *pattern;
    Severity severity;
    const char *description;
} Signature;

extern const Signature SIGNATURES[];
extern const int SIGNATURE_COUNT;

const char *severity_to_string(Severity sev);

#endif
