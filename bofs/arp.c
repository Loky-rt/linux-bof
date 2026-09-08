/// arp_enum.c — ARP table enumeration
/// gcc -c -o arp_enum.o arp_enum.c -include bof_api.h -Os -fPIC
#include "bof_api.h"
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

void go(char *args, int args_len) {
    char *arp = (char *)0;
    int alen = AxReadFileToBuffer("/proc/net/arp", &arp, 65536);
    if (alen <= 0 || !arp) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cannot read /proc/net/arp\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 ARP Table\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-18s %-20s %-6s %-6s %s\n",
                 "IP ADDRESS", "MAC ADDRESS", "TYPE", "FLAGS", "IFACE");

    lineiter_t it = {arp, alen, 0};
    char line[256];
    int ln_n = 0, count = 0;

    while (next_line(&it, line, sizeof(line))) {
        ln_n++;
        if (ln_n == 1) continue; /* skip header */

        /* Fields: IP HWtype Flags HWaddress Mask Device */
        char ip[64] = "", hwtype[16] = "", flags[16] = "";
        char mac[32] = "", mask[16] = "", dev[32] = "";

        /* Parse space-separated fields */
        char *p = line;
        char *fields[6] = {ip, hwtype, flags, mac, mask, dev};
        int caps[6] = {63, 15, 15, 31, 15, 31};

        for (int f = 0; f < 6 && *p; f++) {
            while (*p == ' ' || *p == '\t') p++;
            int i = 0;
            while (*p && *p != ' ' && *p != '\t' && i < caps[f]) {
                fields[f][i++] = *p++;
            }
            fields[f][i] = '\0';
        }

        if (ip[0] && mac[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-18s %-20s %-6s %-6s %s\n",
                         ip, mac, hwtype, flags, dev);
            count++;
        }
    }

    AxFree(arp);
    char s[48];
    AxSnprintf(s, sizeof(s), "%d entries", count);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s);
}
