/// proc_enum.c — Process tree (ps auxf style)
/// gcc -c -o proc_enum.o proc_enum.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};
#define DT_DIR 4
#define MAX_PROCS 4096
#define MAX_USERS 256

static int is_num(char c) { return c >= '0' && c <= '9'; }
static int atoi_(const char *s) { int v=0; while(*s>='0'&&*s<='9'){v=v*10+(*s-'0');s++;} return v; }

typedef struct {
    int pid, ppid, uid;
    char state;
    long vsz, rss;
    char cmd[300];
} proc_t;

typedef struct { int uid; char name[20]; } umap_t;

static proc_t  procs[MAX_PROCS];
static int     nprocs = 0;
static umap_t  users[MAX_USERS];
static int     nusers = 0;

static void load_users(void) {
    char *pw = (char*)0; int pl = AxReadFileToBuffer("/etc/passwd", &pw, 262144);
    if (pl <= 0 || !pw) return;
    char *p = pw;
    while (p < pw + pl && nusers < MAX_USERS) {
        char *eol = p; while (eol < pw+pl && *eol != '\n') eol++;
        char *c1 = p; while (c1 < eol && *c1 != ':') c1++;
        if (c1 >= eol) { p = eol+1; continue; }
        char *c2 = c1+1; while (c2 < eol && *c2 != ':') c2++;
        if (c2 >= eol) { p = eol+1; continue; }
        char *uid_s = c2+1;
        int nlen = (int)(c1-p); if (nlen > 19) nlen = 19;
        AxMemcpy(users[nusers].name, p, nlen);
        users[nusers].name[nlen] = '\0';
        users[nusers].uid = atoi_(uid_s);
        nusers++;
        p = eol + 1;
    }
    AxFree(pw);
}

static const char *uid_to_name(int uid) {
    for (int i = 0; i < nusers; i++)
        if (users[i].uid == uid) return users[i].name;
    return "?";
}

/* Skip a field in /proc/PID/stat (handles negative numbers) */
static char *skip_stat_field(char *p) {
    while (*p == ' ') p++;
    if (*p == '-') p++;
    while (*p >= '0' && *p <= '9') p++;
    return p;
}

/* Read a (possibly negative) long from stat field */
static long read_stat_long(char **pp) {
    char *p = *pp;
    while (*p == ' ') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    long val = 0;
    while (*p >= '0' && *p <= '9') { val = val*10+(*p-'0'); p++; }
    if (neg) val = -val;
    *pp = p;
    return val;
}

static void collect_proc(int pid) {
    if (nprocs >= MAX_PROCS) return;
    proc_t *pr = &procs[nprocs];
    char path[128];

    /* /proc/PID/stat */
    AxSnprintf(path, sizeof(path), "/proc/%d/stat", pid);
    char *st = (char*)0; int sl = AxReadFileToBuffer(path, &st, 1024);
    if (sl <= 0 || !st) return;

    /* Find closing ')' for comm field */
    char *cp = st + sl - 1;
    while (cp > st && *cp != ')') cp--;
    if (cp <= st) { AxFree(st); return; }

    pr->pid = pid;
    char *f = cp + 2; /* skip ") " */
    pr->state = *f;
    f += 2; /* skip "S " */
    pr->ppid = atoi_(f);

    /* Advance field by field: 4=ppid → 24=rss */
    char *p = f;
    pr->vsz = 0; pr->rss = 0;
    for (int field = 4; field <= 24; field++) {
        while (*p == ' ') p++;
        if (field == 23) {
            pr->vsz = read_stat_long(&p) / 1024; /* bytes → KB */
        } else if (field == 24) {
            pr->rss = read_stat_long(&p) * 4; /* pages → KB */
        } else {
            p = skip_stat_field(p);
        }
    }
    AxFree(st);

    /* /proc/PID/status → Uid */
    AxSnprintf(path, sizeof(path), "/proc/%d/status", pid);
    char *status = (char*)0; int stl = AxReadFileToBuffer(path, &status, 4096);
    pr->uid = -1;
    if (stl > 0 && status) {
        char *ul = AxStrstr(status, "Uid:\t");
        if (ul) pr->uid = atoi_(ul + 5);
        AxFree(status);
    }

    /* /proc/PID/cmdline */
    AxSnprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    char *cl = (char*)0; int cll = AxReadFileToBuffer(path, &cl, 1024);
    pr->cmd[0] = '\0';
    if (cll > 0 && cl) {
        int dl = cll > 290 ? 290 : cll;
        AxMemcpy(pr->cmd, cl, dl);
        for (int i = 0; i < dl; i++) if (pr->cmd[i] == '\0') pr->cmd[i] = ' ';
        pr->cmd[dl] = '\0';
        while (dl > 0 && pr->cmd[dl-1] == ' ') pr->cmd[--dl] = '\0';
        AxFree(cl);
    } else {
        AxSnprintf(path, sizeof(path), "/proc/%d/comm", pid);
        char *comm = (char*)0; int coml = AxReadFileToBuffer(path, &comm, 128);
        if (coml > 0 && comm) {
            if (comm[coml-1] == '\n') comm[coml-1] = '\0';
            AxSnprintf(pr->cmd, sizeof(pr->cmd), "[%s]", comm);
            AxFree(comm);
        }
    }

    nprocs++;
}

/* ── Tree rendering ── */

/* Truncate username to 8 chars like ps (7 + '+' for overflow) */
static void trunc_user(const char *name, char *out) {
    int len = AxStrlen(name);
    if (len <= 8) {
        AxStrcpy(out, name);
    } else {
        AxMemcpy(out, name, 7);
        out[7] = '+';
        out[8] = '\0';
    }
}

static void print_proc(proc_t *pr, int depth, int is_last[]) {
    char prefix[128];
    int pi = 0;
    for (int i = 0; i < depth && pi < 100; i++) {
        if (i == depth - 1) {
            if (is_last[i]) { prefix[pi++]='\\'; prefix[pi++]='_'; prefix[pi++]=' '; }
            else            { prefix[pi++]='|'; prefix[pi++]='_'; prefix[pi++]=' '; }
        } else {
            if (is_last[i]) { prefix[pi++]=' '; prefix[pi++]=' '; prefix[pi++]=' '; }
            else            { prefix[pi++]='|'; prefix[pi++]=' '; prefix[pi++]=' '; }
        }
    }
    prefix[pi] = '\0';

    char udisp[10];
    trunc_user(uid_to_name(pr->uid), udisp);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\xe2\x94\x82  %-8s %5d %5d %c %8ld %7ld %s%s\n",
        udisp, pr->pid, pr->ppid, pr->state, pr->vsz, pr->rss, prefix, pr->cmd);
}

static void print_tree(int ppid, int depth, int is_last[]) {
    if (depth > 20) return;

    int children[512];
    int nch = 0;
    for (int i = 0; i < nprocs && nch < 512; i++) {
        if (procs[i].ppid == ppid && procs[i].pid != ppid)
            children[nch++] = i;
    }

    for (int c = 0; c < nch; c++) {
        is_last[depth] = (c == nch - 1) ? 1 : 0;
        print_proc(&procs[children[c]], depth, is_last);
        print_tree(procs[children[c]].pid, depth + 1, is_last);
    }
}

void go(char *args, int args_len) {
    nprocs = 0; nusers = 0;
    load_users();

    int dfd = AxOpenDir("/proc");
    if (dfd < 0) { BeaconPrintf(CALLBACK_ERROR, "[!] Cannot open /proc\n"); return; }
    char db[8192];
    while (1) {
        int nr = AxReadDir(dfd, db, sizeof(db)); if (nr <= 0) break;
        int p = 0;
        while (p < nr) {
            struct linux_dirent64 *e = (struct linux_dirent64*)(db+p);
            if (e->d_type == DT_DIR && is_num(e->d_name[0])) {
                int pid = atoi_(e->d_name);
                if (pid > 0) collect_proc(pid);
            }
            p += e->d_reclen;
        }
    }
    AxCloseFile(dfd);

    BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 Process Tree (%d processes)\n", nprocs);
    BeaconPrintf(CALLBACK_OUTPUT,
        "\xe2\x94\x82  %-8s %5s %5s %s %8s %7s %s\n",
        "USER", "PID", "PPID", "S", "VSZ(kB)", "RSS(kB)", "COMMAND");
    BeaconPrintf(CALLBACK_OUTPUT,
        "\xe2\x94\x82  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n");

    int is_last[64];
    AxMemset(is_last, 0, sizeof(is_last));

    for (int i = 0; i < nprocs; i++) {
        if (procs[i].ppid == 0) {
            print_proc(&procs[i], 0, is_last);
            print_tree(procs[i].pid, 1, is_last);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %d processes\n\n", nprocs);
}
