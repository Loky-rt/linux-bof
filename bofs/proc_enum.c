/// proc_enum.c — Process tree (ps auxf clone, VSZ/RSS in KB, aligned)
/// gcc -c -o proc_enum.o proc_enum.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};
#define DT_DIR 4
#define MAX_PROCS       4096
#define MAX_USERS       256
#define MAX_CHILDREN    1024

#define USR_WIDTH    8
#define PID_WIDTH    6
#define CPU_WIDTH    5
#define MEM_WIDTH    4
#define VSZ_WIDTH   10
#define RSS_WIDTH    8
#define TTY_WIDTH    5
#define STAT_WIDTH   6
#define TIME_WIDTH   5
#define CMD_BUF     300
#define TREE_BASE    3

#define BOF_LONG_MAX  ((long)(~0UL >> 1))
#define BOF_LONG_MIN  (-BOF_LONG_MAX - 1)
#define BOF_INT_MAX   ((int)(~0U >> 1))

extern long LIBC$sysconf(int);
#define SC_CLK_TCK   2
#define SC_PAGESIZE  30

static int atoi_sat_(const char *s, int *out) {
    if (!s || !*s) return 0;
    int v = 0;
    int any = 0;
    while (*s >= '0' && *s <= '9') {
        int digit = *s - '0';
        if (v > (BOF_INT_MAX - digit) / 10) {
            *out = BOF_INT_MAX;
            return 1;
        }
        v = v * 10 + digit;
        s++;
        any = 1;
    }
    if (!any) return 0;
    *out = v;
    return 1;
}

static int atoi_(const char *s) {
    int v = 0;
    atoi_sat_(s, &v);
    return v;
}

static int is_numeric_string(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (*s < '0' || *s > '9') return 0;
        s++;
    }
    return 1;
}

static long safe_sum_ticks(long a, long b) {
    if (a < 0) a = 0;
    if (b < 0) b = 0;
    if (a > BOF_LONG_MAX - b) return BOF_LONG_MAX;
    return a + b;
}

static long mul_1000_div(long x, long divisor) {
    if (x <= 0 || divisor <= 0) return 0;

    long q = x / divisor;
    long r = x % divisor;

    if (q > BOF_LONG_MAX / 1000)
        return BOF_LONG_MAX;

    long term1 = q * 1000;

    long term2 = 0;
    long rem = 0;
    for (int i = 0; i < 1000; i++) {
        if (rem >= divisor - r) {
            rem -= divisor - r;
            term2++;
        } else {
            rem += r;
        }
    }

    if (term1 > BOF_LONG_MAX - term2)
        return BOF_LONG_MAX;
    return term1 + term2;
}

typedef struct {
    int pid, ppid, uid;
    char state;
    char stat_extra[8];
    int tty_nr;
    long utime, stime;
    long starttime;
    long vsz, rss;              /* KB */
    long nice_val;
    long session;
    long num_threads;
    long tpgid;
    char cmd[CMD_BUF];
} proc_t;

typedef struct { int uid; char name[20]; } umap_t;

static proc_t  procs[MAX_PROCS];
static int     nprocs = 0;
static umap_t  users[MAX_USERS];
static int     nusers = 0;

static long    g_uptime_ticks = 0;
static long    g_memtotal_kb = 0;
static long    g_clk_tck = 100;
static long    g_page_size = 4096;

static int     g_skipped_pids = 0;
static int     g_dropped_children = 0;

static void load_users(void) {
    char *pw = (char*)0; int pl = AxReadFileToBuffer("/etc/passwd", &pw, 262144);
    if (pl <= 0) { if (pw) AxFree(pw); return; }
    char *p = pw;
    while (p < pw + pl && nusers < MAX_USERS) {
        char *eol = p; while (eol < pw+pl && *eol != '\n') eol++;
        char *c1 = p; while (c1 < eol && *c1 != ':') c1++;
        if (c1 >= eol) { p = (eol < pw+pl) ? eol+1 : pw+pl; continue; }
        char *c2 = c1+1; while (c2 < eol && *c2 != ':') c2++;
        if (c2 >= eol) { p = (eol < pw+pl) ? eol+1 : pw+pl; continue; }
        char *uid_s = c2+1;
        int nlen = (int)(c1-p); if (nlen > 19) nlen = 19;
        AxMemcpy(users[nusers].name, p, nlen);
        users[nusers].name[nlen] = '\0';
        int uid = -1;
        if (!atoi_sat_(uid_s, &uid)) uid = -1;
        users[nusers].uid = uid;
        nusers++;
        p = (eol < pw+pl) ? eol+1 : pw+pl;
    }
    AxFree(pw);
}

static const char *uid_to_name(int uid) {
    for (int i = 0; i < nusers; i++)
        if (users[i].uid == uid) return users[i].name;
    return "?";
}

static int read_stat_long(const char **pp, const char *end, long *out) {
    const char *p = *pp;
    while (p < end && *p == ' ') p++;
    if (p >= end) return 0;

    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') { p++; }
    if (p >= end) return 0;

    unsigned long limit = neg
        ? (unsigned long)BOF_LONG_MAX + 1UL
        : (unsigned long)BOF_LONG_MAX;

    unsigned long val = 0;
    int any = 0;

    while (p < end && *p >= '0' && *p <= '9') {
        unsigned long digit = (unsigned long)(*p - '0');
        if (val > (limit - digit) / 10UL) return 0;
        val = val * 10UL + digit;
        p++;
        any = 1;
    }
    if (!any) return 0;

    if (neg) {
        *out = (val == (unsigned long)BOF_LONG_MAX + 1UL)
            ? BOF_LONG_MIN
            : -(long)val;
    } else {
        *out = (long)val;
    }

    *pp = p;
    return 1;
}

static int accumulate_digits(const char **pp, long *out) {
    const char *p = *pp;
    long v = 0;
    int any = 0;
    while (*p >= '0' && *p <= '9') {
        long digit = *p - '0';
        if (v > (BOF_LONG_MAX - digit) / 10) return 0;
        v = v * 10 + digit;
        p++;
        any = 1;
    }
    if (!any) return 0;
    *out = v;
    *pp = p;
    return 1;
}

static void load_uptime(void) {
    char *buf = (char*)0; int n = AxReadFileToBuffer("/proc/uptime", &buf, 256);
    if (n <= 0) { if (buf) AxFree(buf); return; }
    const char *p = buf;
    while (*p == ' ') p++;

    long whole = 0;
    if (!accumulate_digits(&p, &whole)) { AxFree(buf); return; }

    long frac_ticks = 0;
    if (*p == '.') {
        p++;
        const char *frac_start = p;
        long acc = 0;
        long divisor = 1;
        int digits = 0;
        while (*p >= '0' && *p <= '9' && digits < 6) {
            if (acc > (BOF_LONG_MAX - 9) / 10) break;
            acc = acc*10 + (*p-'0');
            divisor *= 10;
            digits++;
            p++;
        }
        (void)frac_start;
        if (digits > 0 && g_clk_tck > 0) {

            if (acc > BOF_LONG_MAX / g_clk_tck) frac_ticks = BOF_LONG_MAX;
            else frac_ticks = (acc * g_clk_tck) / divisor;
        }
    }

    if (g_clk_tck > 0 && whole > (BOF_LONG_MAX - frac_ticks) / g_clk_tck) {
        g_uptime_ticks = BOF_LONG_MAX;
    } else {
        g_uptime_ticks = whole * g_clk_tck + frac_ticks;
    }
    AxFree(buf);
}

static void load_meminfo(void) {
    char *buf = (char*)0; int n = AxReadFileToBuffer("/proc/meminfo", &buf, 8192);
    if (n <= 0) { if (buf) AxFree(buf); return; }
    char *p = AxStrstr(buf, "MemTotal:");
    if (p) {
        p += 9;
        while (*p == ' ' || *p == '\t') p++;
        long v = 0;
        if (accumulate_digits((const char**)&p, &v)) {
            g_memtotal_kb = v;
        }
    }
    AxFree(buf);
}

static void resolve_runtime_consts(void) {
    long v;
    v = LIBC$sysconf(SC_CLK_TCK);
    if (v > 0) g_clk_tck = v;
    v = LIBC$sysconf(SC_PAGESIZE);
    if (v > 0) g_page_size = v;
}

static int is_valid_state(char c) {
    return c=='R' || c=='S' || c=='D' || c=='Z' || c=='T' || c=='t'
        || c=='X' || c=='x' || c=='K' || c=='W' || c=='P' || c=='I';
}

static int parse_stat(const char *st, int sl, int pid, proc_t *pr) {
    pr->pid = pid;

    const char *end = st + sl;

    const char *lp = st;
    while (lp < end && *lp != '(') lp++;
    if (lp >= end) return 0;

    const char *cp = end - 1;
    int found = 0;
    while (cp > lp) {
        if (*cp == ')' &&
            end - cp >= 4 &&
            cp[1] == ' ' &&
            is_valid_state(cp[2]) &&
            cp[3] == ' ') {
            found = 1;
            break;
        }
        cp--;
    }
    if (!found) return 0;

    pr->state = cp[2];

    const char *p = cp + 4;
    while (p < end && *p == ' ') p++;

    long vals[25];
    for (int i = 0; i < 25; i++) vals[i] = 0;
    vals[20] = 1;

    for (int field = 4; field <= 24; field++) {
        long v;
        if (!read_stat_long(&p, end, &v)) return 0;
        if (field < 25) vals[field] = v;
    }

    pr->ppid        = (int)vals[4];
    pr->session     = vals[6];
    pr->tty_nr      = (int)vals[7];
    pr->tpgid       = vals[8];
    pr->utime       = vals[14];
    pr->stime       = vals[15];
    pr->nice_val    = vals[19];
    pr->num_threads = vals[20];
    pr->starttime   = vals[22];

    long vsz_bytes = vals[23];
    long rss_pages = vals[24];
    if (rss_pages < 0) rss_pages = 0;
    if (vsz_bytes < 0) vsz_bytes = 0;

    pr->vsz = vsz_bytes / 1024;

    if (g_page_size > 0) {
        unsigned long pages = (unsigned long)rss_pages;
        unsigned long page = (unsigned long)g_page_size;
        unsigned long kb;
        if (pages > (unsigned long)BOF_LONG_MAX / page) {
            kb = (unsigned long)BOF_LONG_MAX;
        } else {
            kb = pages * page / 1024UL;
        }
        pr->rss = (long)kb;
    } else {
        pr->rss = 0;
    }

    return 1;
}

static void collect_proc(int pid) {
    if (nprocs >= MAX_PROCS) { g_skipped_pids++; return; }
    proc_t *pr = &procs[nprocs];
    char path[128];

    AxSnprintf(path, sizeof(path), "/proc/%d/stat", pid);
    char *st = (char*)0; int sl = AxReadFileToBuffer(path, &st, 1024);
    if (sl <= 0 || !st) { if (st) AxFree(st); return; }
    if (!parse_stat(st, sl, pid, pr)) { AxFree(st); return; }
    AxFree(st);

    AxSnprintf(path, sizeof(path), "/proc/%d/status", pid);
    char *status = (char*)0; int stl = AxReadFileToBuffer(path, &status, 4096);
    pr->uid = -1;
    int has_locked_mem = 0;
    if (stl > 0 && status) {
        char *ul = AxStrstr(status, "Uid:\t");
        if (ul) {
            int uid = -1;
            if (atoi_sat_(ul + 5, &uid)) pr->uid = uid;
        }
        char *vl = AxStrstr(status, "VmLck:");
        if (vl) {
            vl += 6;
            while (*vl == ' ' || *vl == '\t') vl++;
            long v = 0;
            while (*vl >= '0' && *vl <= '9') { v = v*10 + (*vl-'0'); vl++; }
            if (v > 0) has_locked_mem = 1;
        }
        AxFree(status);
    } else {
        if (status) AxFree(status);
    }

    pr->stat_extra[0] = '\0';
    {
        char *e = pr->stat_extra;
        int n = 0;
        if (pr->nice_val < 0)        e[n++] = '<';
        else if (pr->nice_val > 0)   e[n++] = 'N';
        if (has_locked_mem)          e[n++] = 'L';
        if (pr->session > 0 && pr->session == pr->pid) e[n++] = 's';
        if (pr->num_threads > 1)     e[n++] = 'l';
        if (pr->tpgid > 0 && pr->tpgid == pr->pid) e[n++] = '+';
        e[n] = '\0';
    }

    AxSnprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    char *cl = (char*)0; int cll = AxReadFileToBuffer(path, &cl, 4096);
    pr->cmd[0] = '\0';
    int cmd_has_content = 0;
    if (cll > 0 && cl) {
        int dl = cll > CMD_BUF - 1 ? CMD_BUF - 1 : cll;
        AxMemcpy(pr->cmd, cl, dl);
        for (int i = 0; i < dl; i++) if (pr->cmd[i] == '\0') pr->cmd[i] = ' ';
        pr->cmd[dl] = '\0';
        while (dl > 0 && pr->cmd[dl-1] == ' ') pr->cmd[--dl] = '\0';
        if (pr->cmd[0] != '\0') cmd_has_content = 1;
        AxFree(cl);
    } else {
        if (cl) AxFree(cl);
    }
    if (!cmd_has_content) {
        AxSnprintf(path, sizeof(path), "/proc/%d/comm", pid);
        char *comm = (char*)0; int coml = AxReadFileToBuffer(path, &comm, 128);
        if (coml > 0 && comm) {
            if (comm[coml-1] == '\n') comm[coml-1] = '\0';
            AxSnprintf(pr->cmd, sizeof(pr->cmd), "[%s]", comm);
            AxFree(comm);
        } else {
            if (comm) AxFree(comm);
        }
    }

    nprocs++;
}

static void fmt_user(const char *name, char *out) {
    int len = AxStrlen(name);
    if (len > USR_WIDTH) {
        AxMemcpy(out, name, USR_WIDTH - 1);
        out[USR_WIDTH - 1] = '+';
        out[USR_WIDTH] = '\0';
        return;
    }
    AxMemcpy(out, name, len);
    for (int i = len; i < USR_WIDTH; i++) out[i] = ' ';
    out[USR_WIDTH] = '\0';
}

static void fmt_cpu(proc_t *pr, char *out, int sz) {
    long ticks = safe_sum_ticks(pr->utime, pr->stime);
    if (ticks == 0) { AxSnprintf(out, sz, "0.0"); return; }

    long elapsed_ticks = g_uptime_ticks - pr->starttime;
    if (elapsed_ticks <= 0) elapsed_ticks = 1;

    long cpu_tenths = mul_1000_div(ticks, elapsed_ticks);
    long whole = cpu_tenths / 10;
    long frac  = cpu_tenths % 10;
    AxSnprintf(out, sz, "%ld.%ld", whole, frac);
}

static void fmt_mem(proc_t *pr, char *out, int sz) {
    if (g_memtotal_kb <= 0) { AxSnprintf(out, sz, "0.0"); return; }

    long mem_tenths = mul_1000_div(pr->rss, g_memtotal_kb);
    long whole = mem_tenths / 10;
    long frac  = mem_tenths % 10;
    AxSnprintf(out, sz, "%ld.%ld", whole, frac);
}

static void fmt_tty(proc_t *pr, char *out, int sz) {
    if (pr->tty_nr == 0) { AxSnprintf(out, sz, "?"); return; }
    int dev = pr->tty_nr;
    int major = (dev >> 8) & 0xfff;
    int minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    if (major == 136)      AxSnprintf(out, sz, "pts/%d", minor);
    else if (major == 4) {
        if (minor < 64) AxSnprintf(out, sz, "tty%d", minor);
        else            AxSnprintf(out, sz, "ttyS%d", minor - 64);
    } else                 AxSnprintf(out, sz, "?");
}

static void fmt_stat(proc_t *pr, char *out, int sz) {
    int n = 0;
    out[n++] = pr->state;
    for (int i = 0; pr->stat_extra[i] && n < sz - 1; i++)
        out[n++] = pr->stat_extra[i];
    out[n] = '\0';
}

static void fmt_time(proc_t *pr, char *out, int sz) {
    long ticks = safe_sum_ticks(pr->utime, pr->stime);
    long clk = g_clk_tck > 0 ? g_clk_tck : 100;
    long secs = ticks / clk;
    AxSnprintf(out, sz, "%ld:%02ld", secs / 60, secs % 60);
}

static void build_prefix(int depth, const int *is_last, char *out, int out_sz) {
    int pi = 0;
    int lim = out_sz - 8;
    for (int i = 0; i < TREE_BASE && pi < lim; i++) out[pi++] = ' ';
    for (int i = 0; i < depth && pi < lim; i++) {
        if (i == depth - 1) {
            const char *conn = is_last[i]
                ? "\xe2\x94\x94\xe2\x94\x80 "
                : "\xe2\x94\x9c\xe2\x94\x80 ";
            for (int k = 0; conn[k] && pi < lim; k++) out[pi++] = conn[k];
        } else {
            const char *col = is_last[i] ? "   " : "\xe2\x94\x82  ";
            for (int k = 0; col[k] && pi < lim; k++) out[pi++] = col[k];
        }
    }
    out[pi] = '\0';
}

static void print_proc(proc_t *pr, int depth, const int *is_last) {
    char prefix[256];
    build_prefix(depth, is_last, prefix, sizeof(prefix));

    char udisp[USR_WIDTH + 1];
    fmt_user(uid_to_name(pr->uid), udisp);

    char cpu_s[16], mem_s[16], tty_s[16], stat_s[16], time_s[16];
    fmt_cpu(pr, cpu_s, sizeof(cpu_s));
    fmt_mem(pr, mem_s, sizeof(mem_s));
    fmt_tty(pr, tty_s, sizeof(tty_s));
    fmt_stat(pr, stat_s, sizeof(stat_s));
    fmt_time(pr, time_s, sizeof(time_s));

    BeaconPrintf(CALLBACK_OUTPUT,
        "\xe2\x94\x82  %s %*d %*s %*s %*ld %*ld %-*s %-*s %*s %s%s\n",
        udisp,
        PID_WIDTH,  pr->pid,
        CPU_WIDTH,  cpu_s,
        MEM_WIDTH,  mem_s,
        VSZ_WIDTH,  pr->vsz,
        RSS_WIDTH,  pr->rss,
        TTY_WIDTH,  tty_s,
        STAT_WIDTH, stat_s,
        TIME_WIDTH, time_s,
        prefix, pr->cmd);
}

static void print_tree(int ppid, int depth, int is_last[]) {
    if (depth > 20) return;

    int children[MAX_CHILDREN];
    int nch = 0;
    for (int i = 0; i < nprocs; i++) {
        if (procs[i].ppid == ppid && procs[i].pid != ppid) {
            if (nch < MAX_CHILDREN) children[nch++] = i;
            else { g_dropped_children++; }
        }
    }
    for (int c = 0; c < nch; c++) {
        is_last[depth] = (c == nch - 1) ? 1 : 0;
        print_proc(&procs[children[c]], depth, is_last);
        print_tree(procs[children[c]].pid, depth + 1, is_last);
    }
}

static int ppid_exists(int ppid) {
    if (ppid == 0) return 1;
    for (int i = 0; i < nprocs; i++)
        if (procs[i].pid == ppid) return 1;
    return 0;
}

static void print_separator(void) {
    int total = USR_WIDTH + 1 + PID_WIDTH + 1 + CPU_WIDTH + 1 + MEM_WIDTH + 1
              + VSZ_WIDTH + 1 + RSS_WIDTH + 1 + TTY_WIDTH + 1 + STAT_WIDTH + 1
              + TIME_WIDTH + 1 + 26;
    char line[512];
    int n = 0;
    const char *bar = "\xe2\x94\x80";
    line[n++] = '\xe2'; line[n++] = '\x94'; line[n++] = '\x82';
    line[n++] = ' '; line[n++] = ' ';
    for (int i = 0; i < total && n + 3 < (int)sizeof(line); i++) {
        line[n++] = bar[0]; line[n++] = bar[1]; line[n++] = bar[2];
    }
    line[n++] = '\n';
    line[n] = '\0';
    BeaconOutput(CALLBACK_OUTPUT, line, n);
}

void go(char *args, int args_len) {
    nprocs = 0; nusers = 0;
    g_skipped_pids = 0;
    g_dropped_children = 0;

    resolve_runtime_consts();
    load_users();
    load_uptime();
    load_meminfo();

    int dfd = AxOpenDir("/proc");
    if (dfd < 0) { BeaconPrintf(CALLBACK_ERROR, "[!] Cannot open /proc\n"); return; }

    char db[8192];
    while (1) {
        int nr = AxReadDir(dfd, db, sizeof(db)); if (nr <= 0) break;
        int p = 0;
        while (p < nr) {
            if (nr - p < (int)sizeof(struct linux_dirent64))
                break;

            struct linux_dirent64 *e = (struct linux_dirent64*)(db + p);

            if (e->d_reclen < sizeof(struct linux_dirent64) ||
                e->d_reclen > nr - p)
                break;

            int name_off = (int)((char*)e->d_name - (char*)e);
            int name_max = (int)e->d_reclen - name_off;
            if (name_max > 0) {
                int name_len = 0;
                while (name_len < name_max && e->d_name[name_len]) name_len++;
                if (name_len < name_max && name_len > 0) {
                    if ((e->d_type == DT_DIR || e->d_type == 0) &&
                        is_numeric_string(e->d_name)) {
                        int pid = 0;
                        if (atoi_sat_(e->d_name, &pid) && pid > 0)
                            collect_proc(pid);
                    }
                }
            }

            p += e->d_reclen;
        }
    }
    AxCloseFile(dfd);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n\xe2\x94\x8c\xe2\x94\x80 Process Tree (%d processes)\n", nprocs);
    BeaconPrintf(CALLBACK_OUTPUT,
        "\xe2\x94\x82  %-*s %*s %*s %*s %*s %*s %-*s %-*s %*s %s\n",
        USR_WIDTH,  "USER",
        PID_WIDTH,  "PID",
        CPU_WIDTH,  "%CPU",
        MEM_WIDTH,  "%MEM",
        VSZ_WIDTH,  "VSZ",
        RSS_WIDTH,  "RSS",
        TTY_WIDTH,  "TTY",
        STAT_WIDTH, "STAT",
        TIME_WIDTH, "TIME",
        "COMMAND");
    print_separator();

    int is_last[64];
    AxMemset(is_last, 0, sizeof(is_last));

    for (int i = 0; i < nprocs; i++) {
        if (procs[i].ppid == 0) {
            print_proc(&procs[i], 0, is_last);
            print_tree(procs[i].pid, 1, is_last);
        }
    }

    int orphans = 0;
    for (int i = 0; i < nprocs; i++) {
        if (procs[i].ppid != 0 && !ppid_exists(procs[i].ppid)) {
            if (orphans == 0)
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\xe2\x94\x82  --- parent not visible in snapshot ---\n");
            print_proc(&procs[i], 1, is_last);
            orphans++;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %d processes\n\n", nprocs);

    if (g_skipped_pids > 0)
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] MAX_PROCS=%d reached, %d PID(s) skipped\n",
            MAX_PROCS, g_skipped_pids);
    if (g_dropped_children > 0)
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] MAX_CHILDREN=%d reached. Some branches of the tree may be incomplete.\n",
            MAX_CHILDREN);
}
