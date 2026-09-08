/// timestomp.c — Modify file timestamps (atime/mtime)
/// gcc -c -o timestomp.o timestomp.c -include bof_api.h -Os -fPIC
/// Args: cstr(target_file), cstr(@reference_file | "YYYY-MM-DD HH:MM:SS")
#include "bof_api.h"

/* Manual datetime epoch (UTC) */

#include <limits.h>
#include <stdlib.h>

static const int mdays[] = {31,28,31,30,31,30,31,31,30,31,30,31};
static int is_leap(int y) { return (y%4==0 && y%100!=0) || y%400==0; }

static long datetime_to_epoch(int y, int mo, int d, int h, int mi, int s) {
    long days = 0;
    for (int i = 1970; i < y; i++) days += is_leap(i) ? 366 : 365;
    for (int i = 1; i < mo; i++) days += (i==2 && is_leap(y)) ? 29 : mdays[i-1];
    days += d - 1;
    return days * 86400L + h * 3600L + mi * 60L + s;
}

static void epoch_to_str(long epoch, char *out, int cap) {
    if (epoch <= 0) { AxStrcpy(out, "(unknown)"); return; }
    long s = epoch % 60; epoch /= 60;
    long mi = epoch % 60; epoch /= 60;
    long h = epoch % 24; epoch /= 24;
    long days = epoch;
    int y = 1970;
    while (1) { int yd = is_leap(y)?366:365; if(days<yd)break; days-=yd; y++; }
    int mo = 1;
    while (1) { int md=(mo==2&&is_leap(y))?29:mdays[mo-1]; if(days<md)break; days-=md; mo++; }
    int d = (int)days + 1;
    AxSnprintf(out, cap, "%04d-%02d-%02d %02ld:%02ld:%02ld", y, mo, d, h, mi, s);
}

/* Parse "YYYY-MM-DD HH:MM:SS" epoch */

static int parse_num(const char **p, int digits) {
    int v = 0;
    for (int i = 0; i < digits; i++) {
        char c = **p;
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
        (*p)++;
    }
    return v;
}

static long parse_timestamp(const char *s) {
    const char *p = s;
    int y = parse_num(&p, 4);  if (*p != '-') return -1; p++;
    int mo = parse_num(&p, 2); if (*p != '-') return -1; p++;
    int d = parse_num(&p, 2);  if (*p != ' ') return -1; p++;
    int h = parse_num(&p, 2);  if (*p != ':') return -1; p++;
    int mi = parse_num(&p, 2); if (*p != ':') return -1; p++;
    int se = parse_num(&p, 2);
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
        h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 59)
        return -1;
    return datetime_to_epoch(y, mo, d, h, mi, se);
}

/* Helper: resolve path to absolute */

static char *resolve_path(const char *path, char *resolved, int cap) {
    if (!path || !resolved || cap <= 0) return NULL;

    if (path[0] == '/') {
        AxStrcpy(resolved, path);
        return resolved;
    }
    if (AxRealpath(path, resolved) != NULL) {
        return resolved;
    }

    char cwd[PATH_MAX];
    if (AxGetCwd(cwd, sizeof(cwd)) > 0) {
        AxSnprintf(resolved, cap, "%s/%s", cwd, path);
        return resolved;
    }

    return NULL;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int tl = 0, sl = 0;
    char *target = BeaconDataExtract(&parser, &tl);
    char *source = BeaconDataExtract(&parser, &sl);

    char resolved_target[PATH_MAX];
    char resolved_source[PATH_MAX];

    if (!target || tl <= 1 || !source || sl <= 1) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Usage: timestomp <target_file> <@reference_file | YYYY-MM-DD HH:MM:SS>\n"
            "  timestomp /tmp/evil.sh @/bin/ls\n"
            "  timestomp /tmp/evil.sh \"2023-01-15 08:30:00\"\n");
        return;
    }

    if (!resolve_path(target, resolved_target, sizeof(resolved_target))) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resolve path: %s\n", target);
        return;
    }
    target = resolved_target;

    unsigned int tmode = 0;
    if (AxFileStat(target, &tmode, (long*)0, (unsigned int*)0, (unsigned int*)0) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Target '%s' not found\n", target);
        return;
    }

    long new_atime = 0, new_mtime = 0;
    char *ref = NULL;

    if (source[0] == '@') {
        /* Reference file mode */
        ref = source + 1;
        if (!resolve_path(ref, resolved_source, sizeof(resolved_source))) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resolve reference: %s\n", ref);
            return;
        }
        ref = resolved_source;
        long ref_atime = 0, ref_mtime = 0;
        if (AxFileTime(ref, &ref_atime, &ref_mtime) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Reference '%s' not found\n", ref);
            return;
        }
        new_atime = ref_atime;
        new_mtime = ref_mtime;

        char ts[32]; epoch_to_str(new_mtime, ts, sizeof(ts));
        BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 Timestomp\n");
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  Source:  %s (reference)\n", ref);
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  Target:  %s\n", target);
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  Stamp:   %s\n", ts);
    } else {
        /* Explicit timestamp mode */
        long epoch = parse_timestamp(source);
        if (epoch < 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Invalid format. Use: YYYY-MM-DD HH:MM:SS\n");
            return;
        }
        new_atime = epoch;
        new_mtime = epoch;

        BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 Timestomp\n");
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  Target:  %s\n", target);
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  Stamp:   %s\n", source);
    }

    /* Get original timestamps for display */
    long orig_atime = 0, orig_mtime = 0;
    AxFileTime(target, &orig_atime, &orig_mtime);
    char orig_a[32], orig_m[32];
    epoch_to_str(orig_atime, orig_a, sizeof(orig_a));
    epoch_to_str(orig_mtime, orig_m, sizeof(orig_m));

    /* Apply */
    if (AxSetFileTime(target, new_atime, new_mtime) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "\xe2\x94\x94\xe2\x94\x80 [!] Failed to set timestamps\n\n");
        return;
    }

    /* Verify */
    long ver_atime = 0, ver_mtime = 0;
    AxFileTime(target, &ver_atime, &ver_mtime);
    char new_a[32], new_m[32];
    epoch_to_str(ver_atime, new_a, sizeof(new_a));
    epoch_to_str(ver_mtime, new_m, sizeof(new_m));

    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-10s %-22s %-22s\n", "", "BEFORE", "AFTER");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-10s %-22s %-22s\n", "Access:", orig_a, new_a);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-10s %-22s %-22s\n", "Modify:", orig_m, new_m);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 [+] Done\n\n");
}
