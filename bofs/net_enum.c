/// net_enum.c — Network enumeration (interfaces, routes, ARP, DNS, connections)
/// gcc -c -o net_enum.o net_enum.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }

static void hex_ip(const char *h, char *o, int cap) {
    unsigned int ip = 0;
    for (int i = 0; i < 8 && h[i]; i++) {
        unsigned int n = 0; char c = h[i];
        if(c>='0'&&c<='9')n=c-'0'; else if(c>='A'&&c<='F')n=c-'A'+10; else if(c>='a'&&c<='f')n=c-'a'+10;
        ip = (ip<<4)|n;
    }
    AxSnprintf(o, cap, "%d.%d.%d.%d", ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF);
}

static int hex4(const char *s) {
    int v=0;
    for(int i=0;i<4&&s[i];i++){int n=0;char c=s[i];
        if(c>='0'&&c<='9')n=c-'0';else if(c>='A'&&c<='F')n=c-'A'+10;else if(c>='a'&&c<='f')n=c-'a'+10;
        v=(v<<4)|n;}
    return v;
}

static const char *tcp_st(int s) {
    switch(s){case 1:return"ESTAB";case 2:return"SYN_S";case 3:return"SYN_R";case 4:return"FIN1";
    case 5:return"FIN2";case 6:return"TIMEW";case 7:return"CLOSE";case 8:return"CLOSW";
    case 9:return"LACK";case 10:return"LISTN";case 11:return"CLSNG";default:return"?";}
}

static void parse_conns(const char *path, const char *proto) {
    char *d = (char*)0; int dl = AxReadFileToBuffer(path, &d, 524288);
    if (dl <= 0 || !d) return;
    sub(proto);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-22s %-22s %s\n", "LOCAL", "REMOTE", "STATE");
    char *line = d; int ln_n = 0;
    while (line < d + dl) {
        char *eol = line; while (eol < d+dl && *eol != '\n') eol++;
        ln_n++;
        if (ln_n > 1) {
            char *p = line; while (p < eol && (*p==' '||*p=='\t')) p++;
            char *c1 = AxStrchr(p, ':');
            if (c1 && c1 < eol) {
                char *loc = c1+2; char *lc = AxStrchr(loc, ':');
                if (lc && lc < eol) {
                    char lih[16]; int ll=(int)(lc-loc); if(ll>15)ll=15; AxMemcpy(lih,loc,ll); lih[ll]='\0';
                    int lp = hex4(lc+1);
                    char *sp = lc+5; while(sp<eol&&*sp==' ')sp++;
                    char *rc = AxStrchr(sp, ':');
                    if (rc && rc < eol) {
                        char rih[16]; int rl=(int)(rc-sp); if(rl>15)rl=15; AxMemcpy(rih,sp,rl); rih[rl]='\0';
                        int rp = hex4(rc+1);
                        char *ss = rc+6; while(ss<eol&&*ss==' ')ss++;
                        int state = hex4(ss);
                        char li[32],ri[32],ls[40],rs[40];
                        hex_ip(lih,li,32); hex_ip(rih,ri,32);
                        AxSnprintf(ls,40,"%s:%d",li,lp); AxSnprintf(rs,40,"%s:%d",ri,rp);
                        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-22s %-22s %s\n", ls, rs, tcp_st(state));
                    }
                }
            }
        }
        line = eol+1;
    }
    AxFree(d);
}

static void parse_dns(void) {
    char *d = (char*)0; int dl = AxReadFileToBuffer("/etc/resolv.conf", &d, 8192);
    if (dl <= 0 || !d) return;
    sub("DNS");
    char *line = d;
    while (line < d+dl) {
        char *eol = line; while(eol<d+dl&&*eol!='\n')eol++;
        int ll=(int)(eol-line);
        if (ll > 0 && line[0] != '#' &&
            (AxStrncmp(line,"nameserver",10)==0||AxStrncmp(line,"search",6)==0||AxStrncmp(line,"domain",6)==0)) {
            char b[256]; if(ll>255)ll=255; AxMemcpy(b,line,ll); b[ll]='\0'; ln(b);
        }
        line = eol+1;
    }
    AxFree(d);
}

static void parse_arp(void) {
    char *d = (char*)0; int dl = AxReadFileToBuffer("/proc/net/arp", &d, 65536);
    if (dl <= 0 || !d) return;
    sub("ARP Table");
    char *line = d; int ln_n = 0;
    while (line < d+dl) {
        char *eol = line; while(eol<d+dl&&*eol!='\n')eol++;
        int ll = (int)(eol-line);
        if (ll > 0) {
            char b[256]; if(ll>255)ll=255; AxMemcpy(b,line,ll); b[ll]='\0';
            if (ln_n == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", b);
            } else {
                ln(b);
            }
        }
        ln_n++; line = eol+1;
    }
    AxFree(d);
}

static void parse_interfaces(void) {
    char *d = (char*)0; int dl = AxReadFileToBuffer("/proc/net/dev", &d, 65536);
    if (dl <= 0 || !d) return;
    sub("Interfaces (RX/TX bytes)");
    char *line = d; int ln_n = 0;
    while (line < d+dl) {
        char *eol = line; while(eol<d+dl&&*eol!='\n')eol++;
        if (ln_n >= 2) { /* skip 2 header lines */
            char *p = line; while(p<eol&&(*p==' '||*p=='\t'))p++;
            char *colon = AxStrchr(p, ':');
            if (colon && colon < eol) {
                char iface[32]; int il = (int)(colon-p); if(il>31)il=31;
                AxMemcpy(iface,p,il); iface[il]='\0';
                /* parse rx_bytes (first number after colon) */
                char *n = colon+1; while(*n==' ')n++;
                long rx=0; while(*n>='0'&&*n<='9'){rx=rx*10+(*n-'0');n++;}
                /* skip 7 fields to get tx_bytes */
                for(int i=0;i<7;i++){while(*n==' ')n++;while(*n>='0'&&*n<='9')n++;}
                while(*n==' ')n++;
                long tx=0; while(*n>='0'&&*n<='9'){tx=tx*10+(*n-'0');n++;}
                char b[128];
                AxSnprintf(b, sizeof(b), "%-12s rx=%-12ld tx=%-12ld", iface, rx, tx);
                ln(b);
            }
        }
        ln_n++; line = eol+1;
    }
    AxFree(d);
}

void go(char *args, int args_len) {
    hdr("Network Enumeration");
    parse_interfaces();
    parse_dns();
    parse_arp();
    parse_conns("/proc/net/tcp", "TCP Connections");
    parse_conns("/proc/net/tcp6", "TCP6 Connections");
    fin("Network enumeration complete");
}
