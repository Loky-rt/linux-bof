#include "bof_api.h"

#define AX_AF_INET     2
#define AX_SOCK_DGRAM  2
#define AX_SOL_SOCKET  1
#define AX_SO_RCVTIMEO 20

#define MAX_NS                4
#define MAX_CNAMES_PER_RESP   8
#define MAX_CNAME_LEN         256

#define DNS_T_A      1
#define DNS_T_CNAME  5
#define DNS_T_PTR    12

#define DNS_RC_NOERROR   0
#define DNS_RC_FORMERR   1
#define DNS_RC_SERVFAIL  2
#define DNS_RC_NXDOMAIN  3
#define DNS_RC_NOTIMP    4
#define DNS_RC_REFUSED   5

struct ax_in_addr  { unsigned int s_addr; };
struct ax_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct ax_in_addr sin_addr;
    char sin_zero[8];
};
struct ax_timeval { long tv_sec; long tv_usec; };

/* Parseo robusto de /etc/resolv.conf */
static int parse_resolv_conf(char ns[][64], int max_ns) {
    int count = 0;
    char *d = (char *)0;

    int dl = AxReadFileToBuffer("/etc/resolv.conf", &d, 16384);
    if (dl <= 0 || !d) return 0;

    char *p   = d;
    char *end = d + dl;

    while (p < end && count < max_ns) {
        char *line_start = p;
        char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;

        while (line_start < line_end &&
               (*line_start == ' ' || *line_start == '\t'))
            line_start++;

        if (line_start < line_end &&
            *line_start != '#' && *line_start != ';') {

            static const char kw[] = "nameserver";
            const int kw_len = 10;
            int is_kw = 1;

            if (line_end - line_start < kw_len) {
                is_kw = 0;
            } else {
                for (int i = 0; i < kw_len; i++) {
                    if (line_start[i] != kw[i]) { is_kw = 0; break; }
                }
                if (is_kw &&
                    line_start[kw_len] != ' ' &&
                    line_start[kw_len] != '\t')
                    is_kw = 0;
            }

            if (is_kw) {
                char *ip = line_start + kw_len;
                while (ip < line_end && (*ip == ' ' || *ip == '\t')) ip++;

                char tmp[64];
                int len = 0;
                while (ip < line_end && len < 63) {
                    char c = *ip;
                    if (c == ' ' || c == '\t' || c == '#' || c == ';' ||
                        c == '\r' || c == '\n')
                        break;
                    tmp[len++] = c;
                    ip++;
                }
                tmp[len] = '\0';

                if (len > 0) {
                    struct ax_in_addr probe;
                    if (AxInetPton(AX_AF_INET, tmp, &probe) == 1) {
                        int dup = 0;
                        for (int j = 0; j < count; j++) {
                            if (AxStrcmp(ns[j], tmp) == 0) { dup = 1; break; }
                        }
                        if (!dup) {
                            AxStrcpy(ns[count], tmp);
                            count++;
                        }
                    }
                }
            }
        }

        p = (line_end < end) ? line_end + 1 : end;
    }

    AxFree(d);
    return count;
}

static int dns_skip_name(const unsigned char *r, int rl, int off) {
    if (!r || rl <= 0) return -1;
    if (off < 0 || off >= rl) return -1;

    while (off < rl) {
        unsigned char c = r[off];

        if (c == 0x00) return off + 1;

        if ((c & 0xC0) == 0xC0) {
            if (off + 2 > rl) return -1;
            return off + 2;
        }

        if ((c & 0xC0) != 0x00) return -1;
        if (c > 63) return -1;
        if (off + 1 + c > rl) return -1;
        off += 1 + c;
    }
    return -1;
}

static int dns_extract_name(const unsigned char *r, int rl, int off,
                            char *out, int cap) {
    if (!r || rl <= 0 || !out || cap < 2) return -1;
    if (off < 0 || off >= rl) return -1;

    int o = 0;
    int orig_off = -1;
    int jumped = 0;
    int max_jumps = 16;

    while (off < rl && max_jumps-- > 0) {
        unsigned char c = r[off];

        if (c == 0x00) {
            if (!jumped) orig_off = off + 1;
            if (o == 0) {
                if (cap < 2) return -1;
                out[0] = '.';
                out[1] = '\0';
            } else {
                out[o] = '\0';
            }
            return jumped ? orig_off : (off + 1);
        }

        if ((c & 0xC0) == 0xC0) {
            if (off + 2 > rl) return -1;
            int ptr = ((c & 0x3F) << 8) | r[off + 1];
            if (ptr >= off) return -1;
            if (!jumped) {
                orig_off = off + 2;
                jumped = 1;
            }
            off = ptr;
            continue;
        }

        if ((c & 0xC0) != 0x00) return -1;
        if (c > 63) return -1;
        if (off + 1 + c > rl) return -1;

        if (o > 0) {
            if (o + 1 >= cap) return -1;
            out[o++] = '.';
        }

        if (o + c >= cap) return -1;
        AxMemcpy(out + o, r + off + 1, c);
        o += c;
        off += 1 + c;
    }
    return -1;
}

static unsigned short dns_random_id(void) {
    static unsigned int ctr = 0;
    ctr++;
    unsigned int pid = (unsigned int)AxGetPid();
    unsigned int uid = (unsigned int)AxGetUid();
    unsigned int x = pid * 2654435761u ^ uid * 40503u ^ ctr * 2246822519u;
    return (unsigned short)(x ^ (x >> 16));
}

static int is_ipv4_literal(const char *s) {
    struct ax_in_addr tmp;
    return AxInetPton(AX_AF_INET, s, &tmp) == 1;
}

static int make_reverse_name(const char *ipv4, char *out, int cap) {
    struct ax_in_addr a;
    if (AxInetPton(AX_AF_INET, ipv4, &a) != 1) return -1;

    const unsigned char *b = (const unsigned char *)&a.s_addr;
    int n = AxSnprintf(out, cap, "%u.%u.%u.%u.in-addr.arpa",
                       b[3], b[2], b[1], b[0]);
    return n > 0 ? 0 : -1;
}

static int dns_query(const char *hostname, const char *nameserver,
                     int qtype,
                     char ipv4s[][20], int *n4,
                     char cnames[][MAX_CNAME_LEN], int *n_cnames,
                     int max_cnames,
                     char *ptr_out, int ptr_cap,
                     int *rcode_out) {
    *n4 = 0;
    if (n_cnames) *n_cnames = 0;
    if (ptr_out && ptr_cap > 0) ptr_out[0] = '\0';
    if (rcode_out) *rcode_out = -1;

    unsigned char q[512];
    int ql = 0;

    unsigned short qid = dns_random_id();

    q[ql++] = (qid >> 8) & 0xFF;
    q[ql++] = qid & 0xFF;
    q[ql++] = 0x01; q[ql++] = 0x00;
    q[ql++] = 0x00; q[ql++] = 0x01;
    q[ql++] = 0x00; q[ql++] = 0x00;
    q[ql++] = 0x00; q[ql++] = 0x00;
    q[ql++] = 0x00; q[ql++] = 0x00;

    const char *p = hostname;
    while (*p) {
        const char *dot = AxStrchr(p, '.');
        int ll = dot ? (int)(dot - p) : AxStrlen(p);
        if (ll > 63 || ql + ll + 2 > 512) return -1;
        q[ql++] = (unsigned char)ll;
        AxMemcpy(q + ql, p, ll); ql += ll;
        if (dot) p = dot + 1; else break;
    }
    q[ql++] = 0x00;
    q[ql++] = (qtype >> 8) & 0xFF;
    q[ql++] = qtype & 0xFF;
    q[ql++] = 0x00; q[ql++] = 0x01;

    int sock = AxSocket(AX_AF_INET, AX_SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ax_timeval tv = {5, 0};
    AxSetsockopt(sock, AX_SOL_SOCKET, AX_SO_RCVTIMEO, &tv, sizeof(tv));

    struct ax_sockaddr_in ns_addr;
    AxMemset(&ns_addr, 0, sizeof(ns_addr));
    ns_addr.sin_family = AX_AF_INET;
    ns_addr.sin_port   = AxHtons(53);
    AxInetPton(AX_AF_INET, nameserver, &ns_addr.sin_addr);

    if (AxSendto(sock, q, ql, 0, &ns_addr, sizeof(ns_addr)) < 0) {
        AxClose(sock); return -1;
    }

    unsigned char r[512];
    int rl = AxRecvfrom(sock, r, sizeof(r), 0, (void*)0, (void*)0);
    AxClose(sock);
    if (rl < 12) return -1;

    unsigned short rid = (r[0] << 8) | r[1];
    if (rid != qid) return -1;
    if ((r[2] & 0x80) == 0) return -1;

    int rcode = r[3] & 0x0F;
    if (rcode_out) *rcode_out = rcode;

    if (rcode != DNS_RC_NOERROR) return 0;

    int answers = (r[6] << 8) | r[7];
    if (answers == 0) return 0;

    int off = 12;
    int qd = (r[4] << 8) | r[5];
    for (int i = 0; i < qd; i++) {
        off = dns_skip_name(r, rl, off);
        if (off < 0) return -1;
        if (off + 4 > rl) return -1;
        off += 4;
    }

    for (int i = 0; i < answers && off < rl; i++) {
        off = dns_skip_name(r, rl, off);
        if (off < 0) return -1;

        if (off + 10 > rl) break;

        int type = (r[off] << 8) | r[off+1];
        int dlen = (r[off+8] << 8) | r[off+9];
        off += 10;

        if (off + dlen > rl) break;

        if (type == DNS_T_A && dlen == 4 && *n4 < 10) {
            AxSnprintf(ipv4s[*n4], 20, "%d.%d.%d.%d",
                       r[off], r[off+1], r[off+2], r[off+3]);
            (*n4)++;
        }
        else if (type == DNS_T_CNAME && dlen > 0 &&
                 cnames && n_cnames && *n_cnames < max_cnames) {
            if (dns_extract_name(r, rl, off,
                                 cnames[*n_cnames], MAX_CNAME_LEN) > 0) {
                (*n_cnames)++;
            }
        }
        else if (type == DNS_T_PTR && dlen > 0 &&
                 ptr_out && ptr_cap > 0 && ptr_out[0] == '\0') {
            dns_extract_name(r, rl, off, ptr_out, ptr_cap);
        }

        off += dlen;
    }

    return 0;
}

static void print_rcode(int rcode) {
    switch (rcode) {
    case DNS_RC_FORMERR:
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  \xe2\x9c\x97 FORMERR\n");
        break;
    case DNS_RC_SERVFAIL:
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  \xe2\x9c\x97 SERVFAIL\n");
        break;
    case DNS_RC_NXDOMAIN:
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  \xe2\x9c\x97 NXDOMAIN\n");
        break;
    case DNS_RC_NOTIMP:
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  \xe2\x9c\x97 NOTIMP\n");
        break;
    case DNS_RC_REFUSED:
        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  \xe2\x9c\x97 REFUSED\n");
        break;
    default:
        BeaconPrintf(CALLBACK_OUTPUT,
            "\xe2\x94\x82  \xe2\x9c\x97 RCODE %d\n", rcode);
        break;
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int domain_len = 0, server_len = 0;
    char *domain = BeaconDataExtract(&parser, &domain_len);
    char *server = BeaconDataExtract(&parser, &server_len);

    if (!domain || domain_len <= 1) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Usage: nslookup <host[,host...]|ip[,ip...]> [server]\n");
        return;
    }

    char ns_list[MAX_NS][64];
    int  ns_count = 0;

    if (server && server_len > 1) {
        struct ax_in_addr probe;
        if (AxInetPton(AX_AF_INET, server, &probe) == 1) {
            AxStrncpy(ns_list[0], server, 63);
            ns_list[0][63] = '\0';
            ns_count = 1;
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Invalid server IP: %s\n", server);
            return;
        }
    } else {
        ns_count = parse_resolv_conf(ns_list, MAX_NS);
        if (ns_count == 0) {
            AxStrcpy(ns_list[0], "8.8.8.8");
            ns_count = 1;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n\xe2\x94\x8c\xe2\x94\x80 DNS Lookup (server: %s%s)\n",
        ns_list[0],
        ns_count > 1 ? ", ..." : "");

    char hostbuf[1024];
    int dl2 = AxStrlen(domain);
    if (dl2 > 1023) dl2 = 1023;
    AxMemcpy(hostbuf, domain, dl2); hostbuf[dl2] = '\0';

    char *h = hostbuf;
    int total = 0, resolved = 0;

    while (h && *h) {
        char *comma = AxStrchr(h, ',');
        if (comma) *comma = '\0';

        while (*h == ' ' || *h == '\t') h++;
        if (!*h) {
            if (comma) h = comma + 1;
            else break;
            continue;
        }

        total++;

        int  is_ip = is_ipv4_literal(h);
        char query_name[256];
        int  qtype;

        if (is_ip) {
            if (make_reverse_name(h, query_name, sizeof(query_name)) != 0) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\xe2\x94\x9c\xe2\x94\x80 %s\n"
                    "\xe2\x94\x82  \xe2\x9c\x97 invalid IP\n", h);
                continue;
            }
            qtype = DNS_T_PTR;
        } else {
            AxStrncpy(query_name, h, sizeof(query_name) - 1);
            query_name[sizeof(query_name) - 1] = '\0';
            qtype = DNS_T_A;
        }

        char ipv4s[10][20];
        int  n4 = 0;
        char cnames[MAX_CNAMES_PER_RESP][MAX_CNAME_LEN];
        int  n_cnames = 0;
        char ptr_buf[MAX_CNAME_LEN];
        ptr_buf[0] = '\0';
        int  rcode = -1;

        int rc = -1;
        for (int ni = 0; ni < ns_count; ni++) {
            rc = dns_query(query_name, ns_list[ni], qtype,
                           ipv4s, &n4,
                           cnames, &n_cnames, MAX_CNAMES_PER_RESP,
                           ptr_buf, sizeof(ptr_buf),
                           &rcode);
            if (rc == 0) {
                if (rcode == DNS_RC_NOERROR &&
                    (n4 > 0 || n_cnames > 0 || ptr_buf[0]))
                    break;
                if (rcode == DNS_RC_NXDOMAIN) break;
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", h);

        if (rc != 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "\xe2\x94\x82  \xe2\x9c\x97 timeout\n");
        } else if (rcode != DNS_RC_NOERROR) {
            print_rcode(rcode);
        } else if (is_ip) {
            /* Resultado PTR */
            if (ptr_buf[0]) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\xe2\x94\x82  PTR    %s\n", ptr_buf);
                resolved++;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\xe2\x94\x82  \xe2\x9c\x97 no PTR record\n");
            }
        } else {
            /* Resultado A/CNAME */
            if (n4 == 0 && n_cnames == 0) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\xe2\x94\x82  \xe2\x9c\x97 no data\n");
            } else {
                for (int i = 0; i < n_cnames; i++)
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "\xe2\x94\x82  CNAME  %s\n", cnames[i]);

                if (n4 == 0 && n_cnames > 0) {
                    const char *last_cname = cnames[n_cnames - 1];

                    char cname_ips[10][20];
                    int  cname_n4 = 0;
                    char cname2[MAX_CNAMES_PER_RESP][MAX_CNAME_LEN];
                    int  cname2_n = 0;
                    char dummy_ptr[MAX_CNAME_LEN];
                    int  cname2_rcode = -1;

                    for (int ni = 0; ni < ns_count; ni++) {
                        int rc2 = dns_query(last_cname, ns_list[ni], DNS_T_A,
                                            cname_ips, &cname_n4,
                                            cname2, &cname2_n,
                                            MAX_CNAMES_PER_RESP,
                                            dummy_ptr, sizeof(dummy_ptr),
                                            &cname2_rcode);
                        if (rc2 == 0) {
                            if (cname2_rcode == DNS_RC_NOERROR &&
                                (cname_n4 > 0 || cname2_n > 0))
                                break;
                            if (cname2_rcode == DNS_RC_NXDOMAIN) break;
                        }
                    }

                    if (cname2_rcode != DNS_RC_NOERROR &&
                        cname2_rcode != -1) {
                        print_rcode(cname2_rcode);
                    } else {
                        for (int i = 0; i < cname2_n; i++)
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "\xe2\x94\x82  CNAME  %s\n", cname2[i]);

                        for (int i = 0; i < cname_n4; i++)
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "\xe2\x94\x82  A      %s\n", cname_ips[i]);
                    }

                    if (cname_n4 > 0) resolved++;
                } else {
                    for (int i = 0; i < n4; i++)
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "\xe2\x94\x82  A      %s\n", ipv4s[i]);
                    if (n4 > 0) resolved++;
                }
            }
        }

        h = comma ? comma + 1 : (char *)0;
    }

    char s[64];
    AxSnprintf(s, sizeof(s), "%d/%d resolved", resolved, total);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s);
}
