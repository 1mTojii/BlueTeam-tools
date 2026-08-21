#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "scanner.h"
#include "reporter.h"

/*
 * SusStringFinder -- a simple static string scanner.
 *
 * Usage:
 *   SusStringFinder <path>              scan a single file
 *   SusStringFinder -r <directory>      recursively scan a directory
 *
 * Example:
 *   SusStringFinder -r ./suspicious_samples
 */

static int scanned = 0;
static int flagged = 0;
static int matches = 0;

static void scan_and_report(const char *filepath) {

    MatchList match_list;
    matchlist_init(&match_list);

    int result = scan_file(filepath, &match_list);
    scanned++;

    if (result != 0) {
        fprintf(stderr, "  (skipped, could not read: %s)\n", filepath);
        matchlist_free(&match_list);
        return;
    }

    if (match_list.count > 0) {
        print_file_header(filepath);
        for (int i = 0; i < match_list.count; i++) {
            print_match(&match_list.items[i]);
        }
        flagged++;
        matches += match_list.count;
    }

    matchlist_free(&match_list);
}

static void walk_directory(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Could not open directory: %s\n", dirpath);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;  /* couldn't stat it, skip rather than crash */
        }

        if (S_ISDIR(st.st_mode)) {
            walk_directory(full_path);
        } else if (S_ISREG(st.st_mode)) {
            scan_and_report(full_path);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s <file>          scan a single file\n", argv[0]);
        printf("  %s -r <directory>  recursively scan a directory\n", argv[0]);
        return 1;
    }

    print_banner();

    if (strcmp(argv[1], "-r") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: -r requires a directory path.\n");
            return 1;
        }
        walk_directory(argv[2]);
    } else {
        scan_and_report(argv[1]);
    }

    print_summary(scanned, flagged, matches);
    return 0;
}
