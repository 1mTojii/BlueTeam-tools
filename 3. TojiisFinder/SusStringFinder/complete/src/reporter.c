#include <stdio.h>
#include "reporter.h"

#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define CYAN    "\033[36m"
#define YELLOW  "\033[33m"
#define ORANGE  "\033[38;5;208m"
#define RED     "\033[31m"

static const char *severity_color(Severity sev) {
    switch (sev) {
        case SEV_LOW:      return CYAN;
        case SEV_MEDIUM:   return YELLOW;
        case SEV_HIGH:     return ORANGE;
        case SEV_CRITICAL: return RED;
        default:           return RESET;
    }
}

void print_banner(void) {
    printf(BOLD CYAN
        "\n"
        " _____     _ _ _       _____ _           _           \n"
        "|_   _|__ (_|_| )___  |  ___(_)_ __   __| | ___ _ __ \n"
        "  | |/ _ \\| | |// __| | |_  | | '_ \\ / _` |/ _ \\ '__|\n"
        "  | | (_) | | | \\__ \\ |  _| | | | | | (_| |  __/ |   \n"
        "  |_|\\___// |_| |___/ |_|   |_|_| |_|\\__,_|\\___|_|   \n"
        "        |__/                                         \n"
        "        suspicious string scanner -- YARA-lite\n"
        RESET "\n");
}

void print_file_header(const char *filepath) {
    printf(BOLD "\nScanning: " RESET "%s\n", filepath);
}

void print_match(const Match *m) {
    const char *color = severity_color(m->sig->severity);
    const char *sev_str = severity_to_string(m->sig->severity);

    printf("  %s%s[%-8s]%s offset %-8ld pattern: %-20s %s(%s)%s\n",
           BOLD, color, sev_str, RESET, m->offset, m->sig->pattern, DIM, m->sig->description, RESET);
    printf("      %s...%s...%s\n", DIM, m->context, RESET);
}

void print_summary(int scanned, int flagged, int matches) {
    printf("\n" DIM "------------------------------------------------------------" RESET "\n");
    printf(BOLD "Summary" RESET "\n");
    printf("  files scanned : %d\n", scanned);
    printf("  files flagged : %d\n", flagged);
    printf("  total matches : %d\n", matches);
    printf(DIM "------------------------------------------------------------" RESET "\n");
}
