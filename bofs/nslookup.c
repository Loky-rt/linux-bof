/// nslookup.c — DNS lookup via raw UDP query
/// gcc -c -o nslookup.o nslookup.c -include bof_api.h -Os -fPIC
/// Args: BeaconDataParse format — cstr(domain), cstr(server)
#include "bof_api.h"

/* AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_RCVTIMEO, sockaddr_in */
#define AX_AF_INET     2
#define AX_SOCK_DGRAM  2
#define AX_SOL_SOCKET  1
#define AX_SO_RCVTIMEO 20

struct ax_in_addr  { unsigned int s_addr; };
struct ax_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct ax_in_addr sin_addr;
    char sin_zero[8];
};
struct ax_timeval { long tv_sec; long tv_usec; };

static int dns_query(const char *hostname, const char *nameserver,
                     char ipv4s[][20], int *n4) {
    *n4 = 0;
    unsigned char q[512];
    int ql = 0;

    /* DNS header: ID=0x1234, RD=1, QDCOUNT=1 */
    q[ql++]=0x12; q[ql++]=0x34; q[ql++]=0x01; q[ql++]=0x00;
    q[ql++]=0x00; q[ql++]=0x01; q[ql++]=0x00; q[ql++]=0x00;
    q[ql++]=0x00; q[ql++]=0x00; q[ql++]=0x00; q[ql++]=0x00;

    /* Encode hostname labels */
    const char *p = hostname;
    while (*p) {
        const char *dot = AxStrchr(p, '.');
        int ll = dot ? (int)(dot - p) : AxStrlen(p);
        if (ll > 63 || ql + ll + 1 > 500) return -1;
        q[ql++] = (unsigned char)ll;
        AxMemcpy(q + ql, p, ll); ql += ll;
        if (dot) p = dot + 1; else break;
    }
    q[ql++] = 0x00;
    q[ql++]=0x00; q[ql++]=0x01; /* Type A */
    q[ql++]=0x00; q[ql++]=0x01; /* Class IN */

    int sock = AxSocket(AX_AF_INET, AX_SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ax_timeval tv = {5, 0};
    AxSetsockopt(sock, AX_SOL_SOCKET, AX_SO_RCVTIMEO, &tv, sizeof(tv));

    struct ax_sockaddr_in ns_addr;
    AxMemset(&ns_addr, 0, sizeof(ns_addr));
    ns_addr.sin_family = AX_AF_INET;
    ns_addr.sin_port = AxHtons(53);
    AxInetPton(AX_AF_INET, nameserver, &ns_addr.sin_addr);

    if (AxSendto(sock, q, ql, 0, &ns_addr, sizeof(ns_addr)) < 0) {
        AxClose(sock); return -1;
    }

    unsigned char r[512];
    int rl = AxRecvfrom(sock, r, sizeof(r), 0, (void*)0, (void*)0);
    AxClose(sock);
    if (rl < 12) return -1;

    int answers = (r[6] << 8) | r[7];
    if (answers == 0) return -1;

    /* Skip question section */
    int off = 12;
    while (off < rl && r[off] != 0) {
        if ((r[off] & 0xC0) == 0xC0) { off += 2; goto past_q; }
        off += r[off] + 1;
    }
    off++;
past_q:
    off += 4; /* QTYPE + QCLASS */

    /* Parse A records */
    for (int i = 0; i < answers && off < rl; i++) {
        if ((r[off] & 0xC0) == 0xC0) off += 2;
        else { while (off < rl && r[off] != 0) off += r[off]+1; off++; }
        if (off + 10 > rl) break;
        int type = (r[off] << 8) | r[off+1];
        int dlen = (r[off+8] << 8) | r[off+9];
        off += 10;
        if (type == 1 && dlen == 4 && *n4 < 10) {
            AxSnprintf(ipv4s[*n4], 20, "%d.%d.%d.%d",
                       r[off], r[off+1], r[off+2], r[off+3]);
            (*n4)++;
        }
        off += dlen;
    }
    return (*n4 > 0) ? 0 : -1;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int domain_len = 0, server_len = 0;
    char *domain = BeaconDataExtract(&parser, &domain_len);
    char *server = BeaconDataExtract(&parser, &server_len);

    if (!domain || domain_len <= 1) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Usage: nslookup <domain> <server>\n");
        return;
    }

    /* Default nameserver */
    char ns_buf[64];
    if (!server || server_len <= 1) {
        AxStrcpy(ns_buf, "8.8.8.8");
        char *d = (char *)0;
        int dl = AxReadFileToBuffer("/etc/resolv.conf", &d, 8192);
        if (dl > 0 && d) {
            char *ns = AxStrstr(d, "nameserver");
            if (ns) {
                ns += 10; while (*ns == ' ' || *ns == '\t') ns++;
                int i = 0;
                while (ns[i] && ns[i] != '\n' && ns[i] != ' ' && i < 63) {
                    ns_buf[i] = ns[i]; i++;
                }
                ns_buf[i] = '\0';
            }
            AxFree(d);
        }
        server = ns_buf;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 DNS Lookup (server: %s)\n", server);

    char hostbuf[1024];
    int dl2 = AxStrlen(domain);
    if (dl2 > 1023) dl2 = 1023;
    AxMemcpy(hostbuf, domain, dl2); hostbuf[dl2] = '\0';

    char *h = hostbuf;
    int total = 0, resolved = 0;

    while (h && *h) {
        char *comma = AxStrchr(h, ',');
        if (comma) *comma = '\0';
        while (*h == ' ') h++;
        if (!*h) { if (comma) h = comma + 1; else break; continue; }

        total++;
        char ipv4s[10][20];
        int n4 = 0;
        int rc = dns_query(h, server, ipv4s, &n4);

        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", h);
        if (rc == 0) {
            for (int i = 0; i < n4; i++)
                BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  A      %s\n", ipv4s[i]);
            resolved++;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  [-] No response\n");
        }

        h = comma ? comma + 1 : (char *)0;
    }

    char s[64]; AxSnprintf(s, sizeof(s), "%d/%d resolved", resolved, total);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s);
}
