/// sudo_check.c — Sudoers audit + privilege group check
/// gcc -c -o sudo_check.o sudo_check.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }

typedef struct { char *data; int len; int pos; } lineiter_t;
static int next_line(lineiter_t *it, char *out, int cap) {
    if (it->pos >= it->len) return 0;
    int i = 0;
    while (it->pos < it->len && it->data[it->pos] != '\n') {
        if (i < cap - 1) out[i++] = it->data[it->pos];
        it->pos++;
    }
    if (it->pos < it->len) it->pos++;
    out[i] = '\0';
    return 1;
}

static void show_rules(const char *data, int len, const char *src) {
    lineiter_t it = {(char*)data, len, 0};
    char line[1024]; int count = 0;

    while (next_line(&it, line, sizeof(line))) {
        /* skip empty lines and comments */
        char *s = line; while(*s==' '||*s=='\t') s++;
        if (*s == '\0' || *s == '#') continue;

        int np = 0, al = 0;
        for (char *p = s; *p; p++) {
            if (p[0]=='N'&&AxStrncmp(p,"NOPASSWD",8)==0) np=1;
            if (p[0]=='A'&&p[1]=='L'&&p[2]=='L') al=1;
        }
        const char *tag = (np&&al) ? "[!!]" : (np||al) ? "[! ]" : "    ";
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s %s\n", tag, s);
        count++;
    }
    if (!count) { char b[128]; AxSnprintf(b,sizeof(b),"(no active rules in %s)",src); ln(b); }
}

/* Check if 'user' appears as exact match in comma-separated 'members' string */
static int user_in_members(const char *members, const char *user) {
    int ulen = AxStrlen(user);
    if (ulen == 0 || !members || members[0] == '\0') return 0;

    const char *p = members;
    while (p) {
        /* skip leading spaces */
        while (*p == ' ') p++;
        if (AxStrncmp(p, user, ulen) == 0) {
            char after = p[ulen];
            if (after == ',' || after == '\0' || after == '\n' || after == ' ')
                return 1;
        }
        p = AxStrchr(p, ',');
        if (p) p++;
    }
    return 0;
}

void go(char *args, int args_len) {
    hdr("Sudoers Audit");
    ln("[!!] = NOPASSWD+ALL   [! ] = notable");

    /* 1. Read /etc/sudoers */
    char *sd = (char*)0; int sl = AxReadFileToBuffer("/etc/sudoers", &sd, 524288);
    if (sl > 0 && sd) { sub("/etc/sudoers"); show_rules(sd, sl, "/etc/sudoers"); AxFree(sd); }
    else ln("[!] Cannot read /etc/sudoers (need root or sudo group)");

    /* 2. Scan /etc/sudoers.d/ */
    int dfd = AxOpenDir("/etc/sudoers.d");
    if (dfd >= 0) {
        char db[4096];
        while (1) {
            int nr = AxReadDir(dfd, db, sizeof(db)); if (nr<=0) break;
            int p = 0;
            while (p < nr) {
                struct linux_dirent64 *e = (struct linux_dirent64*)(db+p);
                if (e->d_name[0] != '.') {
                    char fp[512]; AxSnprintf(fp, sizeof(fp), "/etc/sudoers.d/%s", e->d_name);
                    char *fd = (char*)0; int fl = AxReadFileToBuffer(fp, &fd, 524288);
                    if (fl > 0 && fd) { sub(fp); show_rules(fd, fl, fp); AxFree(fd); }
                }
                p += e->d_reclen;
            }
        }
        AxCloseFile(dfd);
    }

    /* 3. Current identity */
    sub("Current Identity");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  PID=%-6d UID=%-5d EUID=%-5d%s\n",
                 AxGetPid(), AxGetUid(), AxGetEuid(), AxGetEuid()==0?" (root)":"");

    /* 4. Find current username from /etc/passwd by UID */
    char me[256]; me[0] = '\0';
    char *pw = (char*)0; int pl = AxReadFileToBuffer("/etc/passwd", &pw, 524288);
    if (pw && pl > 0) {
        char uid_s[16]; AxSnprintf(uid_s, sizeof(uid_s), "%d", AxGetUid());
        int usl = AxStrlen(uid_s);
        lineiter_t it = {pw, pl, 0};
        char pline[1024];
        while (next_line(&it, pline, sizeof(pline))) {
            /* user:x:uid:gid:... — find third field */
            char *f[7]; int nf = 0; char *fs = pline;
            for (char *p = pline; *p && nf < 7; p++) {
                if (*p == ':') { *p = '\0'; f[nf++] = fs; fs = p+1; }
            }
            f[nf++] = fs; /* last field */
            if (nf >= 3 && AxStrcmp(f[2], uid_s) == 0) {
                AxStrcpy(me, f[0]);
                break;
            }
        }
        AxFree(pw);
    }
    if (me[0]) { char b[128]; AxSnprintf(b,sizeof(b),"Username: %s",me); ln(b); }

    /* 5. Check privileged group membership — FIXED: search only members field, exact match */
    char *gf = (char*)0; int gl = AxReadFileToBuffer("/etc/group", &gf, 524288);
    if (gf && gl > 0 && me[0]) {
        const char *pg[] = {"sudo","wheel","admin","root","docker","lxd","disk",(const char*)0};
        sub("Privileged Groups");
        int found = 0;

        lineiter_t git = {gf, gl, 0};
        char gline[1024];

        while (next_line(&git, gline, sizeof(gline))) {
            /* group:x:gid:member1,member2,... */
            /* Split by ':' to get fields */
            char *gfields[4]; int gnf = 0; char *gfs = gline;
            for (char *p = gline; *p && gnf < 3; p++) {
                if (*p == ':') { *p = '\0'; gfields[gnf++] = gfs; gfs = p+1; }
            }
            gfields[gnf++] = gfs; /* members field */
            if (gnf < 4) continue;

            /* Check if this is a privileged group */
            for (int i = 0; pg[i]; i++) {
                if (AxStrcmp(gfields[0], pg[i]) == 0) {
                    /* Check ONLY the members field (gfields[3]) for exact username match */
                    if (user_in_members(gfields[3], me)) {
                        char m[128]; AxSnprintf(m,sizeof(m),"[+] Member of '%s'", gfields[0]);
                        ln(m); found++;
                    }
                    break;
                }
            }
        }
        if (!found) ln("[-] Not in privileged groups");
        AxFree(gf);
    }

    fin("Sudoers audit complete");
}
