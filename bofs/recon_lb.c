#include "bof_api.h"

#define MAX_PATH_LEN    256
#define MAX_COMM_LEN    64
#define MAX_LINE_LEN    512
#define MAX_PER_PROC    16

static const char *ci_strstr(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return NULL;
    for (; *hay; hay++) {
        const char *h = hay;
        const char *n = needle;
        while (*h && *n) {
            char hc = *h;
            char nc = *n;
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
            h++; n++;
        }
        if (!*n) return hay;
    }
    return NULL;
}

static const char *basename_of(const char *path) {
    const char *sl = path;
    for (const char *q = path; *q; q++)
        if (*q == '/') sl = q + 1;
    return sl;
}

static int lib_matches(const char *lib_basename, const char *pattern) {
    if (!lib_basename || !pattern || !*pattern) return 0;
    return ci_strstr(lib_basename, pattern) != NULL;
}

static int read_comm(int pid, char *buf, int sz) {
    if (sz <= 0) return 0;
    char path[64];
    AxSnprintf(path, sizeof(path), "/proc/%d/comm", pid);
    char *content = NULL;
    int n = AxReadFileToBuffer(path, &content, 256);
    if (n <= 0 || !content) return 0;
    int len = 0;
    while (len < n && content[len] != '\n' && len < sz - 1) {
        buf[len] = content[len];
        len++;
    }
    buf[len] = '\0';
    AxFree(content);
    return len;
}

static int read_uid(int pid, int *out_uid) {
    char path[64];
    AxSnprintf(path, sizeof(path), "/proc/%d/status", pid);
    char *content = NULL;
    int n = AxReadFileToBuffer(path, &content, 8192);
    if (n <= 0 || !content) return 0;

    char *p = AxStrstr(content, "Uid:");
    if (!p) { AxFree(content); return 0; }
    p += 4;
    while (*p == '\t' || *p == ' ') p++;

    int uid = 0;
    int any = 0;
    while (*p >= '0' && *p <= '9') {
        uid = uid * 10 + (*p - '0');
        p++;
        any = 1;
    }
    AxFree(content);
    if (!any) return 0;
    *out_uid = uid;
    return 1;
}

static int is_critical_process(const char *comm) {
    static const char *crit[] = {
        "systemd", "init",
        "Xorg", "Xwayland", "X",
        "gnome-shell", "gnome-session", "gnome-session-b",
        "gdm", "gdm3", "gdm-session-wor",
        "sddm", "lightdm", "lxdm",
        "kwin_wayland", "kwin_x11", "plasmashell",
        "dbus-daemon", "dbus-broker",
        NULL
    };
    if (!comm || !*comm) return 0;
    for (int i = 0; crit[i]; i++) {
        if (AxStrcmp(comm, crit[i]) == 0) return 1;
    }
    return 0;
}

static int path_already_seen(char (*paths)[MAX_PATH_LEN], int n,
                             const char *path) {
    for (int i = 0; i < n; i++) {
        if (AxStrcmp(paths[i], path) == 0) return 1;
    }
    return 0;
}

static int scan_maps_for_pattern(int pid, const char *pattern,
                                 char (*out_paths)[MAX_PATH_LEN],
                                 int max_matches) {
    char maps_path[64];
    AxSnprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    char *buf = NULL;
    int buf_len = AxReadFileToBuffer(maps_path, &buf, 4 * 1024 * 1024);
    if (buf_len <= 0 || !buf) {
        if (buf) AxFree(buf);
        return 0;
    }

    int matches = 0;
    int line_start = 0;
    for (int i = 0; i <= buf_len; i++) {
        if (i == buf_len || buf[i] == '\n') {
            int llen = i - line_start;
            if (llen > 0 && llen < MAX_LINE_LEN) {
                char line[MAX_LINE_LEN];
                AxMemcpy(line, buf + line_start, llen);
                line[llen] = '\0';

                const char *path = NULL;
                const char *p = line;
                while (*p) {
                    if (*p == '/') path = p;
                    p++;
                }
                if (path && AxStrstr(path, ".so")) {
                    const char *bn = basename_of(path);
                    if (lib_matches(bn, pattern)) {

                        int to_check = matches < max_matches
                                       ? matches : max_matches;
                        if (!path_already_seen(out_paths, to_check, path)) {
                            if (matches < max_matches) {
                                int plen = (int)AxStrlen(path);
                                if (plen >= MAX_PATH_LEN)
                                    plen = MAX_PATH_LEN - 1;
                                AxMemcpy(out_paths[matches], path, plen);
                                out_paths[matches][plen] = '\0';
                            }
                            matches++;
                        }
                    }
                }
            }
            line_start = i + 1;
        }
    }

    AxFree(buf);
    return matches;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int pat_len = 0;
    char *pat_raw = BeaconDataExtract(&parser, &pat_len);
    if (!pat_raw || pat_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] recon_lib: missing pattern. "
                     "Usage: bof recon_lib str:<pattern>\n");
        return;
    }

    char pattern[64];
    int n = pat_len < (int)sizeof(pattern) - 1
            ? pat_len : (int)sizeof(pattern) - 1;
    AxMemcpy(pattern, pat_raw, n);
    pattern[n] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] recon_lib: pattern='%s'\n", pattern);

    int total_matches = 0;
    int procs_with_match = 0;

    int dfd = AxOpenDir("/proc");
    if (dfd < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] cannot open /proc\n");
        return;
    }

    char dbuf[8192];
    for (;;) {
        int nread = AxReadDir(dfd, dbuf, sizeof(dbuf));
        if (nread <= 0) break;

        int off = 0;
        while (off < nread) {
            unsigned short reclen;
            AxMemcpy(&reclen, dbuf + off + 16, 2);
            if (reclen == 0 || off + reclen > nread) break;

            char *name = dbuf + off + 19;

            int is_pid = (*name != '\0');
            int pid = 0;
            for (const char *q = name; *q; q++) {
                if (*q < '0' || *q > '9') { is_pid = 0; break; }
                pid = pid * 10 + (*q - '0');
            }

            if (is_pid && pid > 0) {
                char paths[MAX_PER_PROC][MAX_PATH_LEN];
                int m = scan_maps_for_pattern(pid, pattern,
                                              paths, MAX_PER_PROC);
                if (m > 0) {
                    char comm[MAX_COMM_LEN];
                    if (read_comm(pid, comm, sizeof(comm)) == 0)
                        AxSnprintf(comm, sizeof(comm), "?");

                    int uid = -1;
                    read_uid(pid, &uid);   /* -1 if not readable */

                    procs_with_match++;
                    total_matches += m;

                    const char *mark = is_critical_process(comm)
                                       ? "[!]" : "   ";

                    int to_print = m < MAX_PER_PROC ? m : MAX_PER_PROC;
                    for (int k = 0; k < to_print; k++) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                                     "%s %6d  uid=%-5d  %-16s  %s\n",
                                     mark, pid, uid, comm, paths[k]);
                    }
                    if (m > MAX_PER_PROC) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                                     "        ... and %d more in pid %d\n",
                                     m - MAX_PER_PROC, pid);
                    }
                }
            }

            off += reclen;
        }
    }
    AxCloseFile(dfd);

    if (procs_with_match == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] no process has a library matching '%s'\n",
                     pattern);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] %d process(es) match '%s' (%d unique lib paths)\n",
                     procs_with_match, pattern, total_matches);
    }
}
