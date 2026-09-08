/// portscan.c — TCP port scanner with service fingerprinting
/// gcc -c -o portscan.o portscan.c -include bof_api.h -Os -fPIC
/// Args: BeaconDataParse — cstr(host), cstr(ports)
#include "bof_api.h"

#define AX_AF_INET       2
#define AX_SOCK_STREAM   1
#define AX_SOL_SOCKET    1
#define AX_SO_RCVTIMEO   20
#define AX_SO_ERROR      4
#define AX_F_GETFL       3
#define AX_F_SETFL       4
#define AX_O_NONBLOCK    2048
#define AX_POLLOUT       4
#define AX_ECONNREFUSED  111
#define AX_ETIMEDOUT     110
#define AX_EHOSTUNREACH  113
#define AX_ENETUNREACH   101
#define AX_EINPROGRESS   115

struct ax_in_addr  { unsigned int s_addr; };
struct ax_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct ax_in_addr sin_addr;
    char sin_zero[8];
};
struct ax_timeval { long tv_sec; long tv_usec; };
struct ax_pollfd  { int fd; short events; short revents; };

#define PS_OPEN     1
#define PS_CLOSED   2
#define PS_FILTERED 3
#define PS_ERROR    4

#define CONNECT_TIMEOUT_MS 3000

/* Check if operator sent jobkill (cooperative stop) */
static int should_stop(void) {
    int fd = BeaconGetStopJobEvent();
    if (fd < 0) return 0; /* sync mode — no stop pipe */
    struct ax_pollfd pfd;
    pfd.fd = fd; pfd.events = 1; /* POLLIN */ pfd.revents = 0;
    return (AxPoll(&pfd, 1, 0) > 0) ? 1 : 0;
}
#define BANNER_TIMEOUT_S   2

typedef struct { int port; const char *name; } portdb_t;
static const portdb_t known[] = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
    {80,"HTTP"},{110,"POP3"},{111,"RPCbind"},{135,"MSRPC"},{139,"NetBIOS"},
    {143,"IMAP"},{443,"HTTPS"},{445,"SMB"},{465,"SMTPS"},{587,"SMTP-Sub"},
    {993,"IMAPS"},{995,"POP3S"},{1080,"SOCKS"},{1433,"MSSQL"},{1521,"Oracle"},
    {2049,"NFS"},{2222,"SSH-Alt"},{3306,"MySQL"},{3389,"RDP"},
    {5432,"PostgreSQL"},{5900,"VNC"},{5985,"WinRM"},{6379,"Redis"},
    {6443,"K8s-API"},{8080,"HTTP-Alt"},{8443,"HTTPS-Alt"},{8888,"HTTP-Alt"},
    {9090,"Prometheus"},{9200,"Elastic"},{11211,"Memcached"},
    {27017,"MongoDB"},{0,0}
};

static const char *port_lookup(int p) {
    for (int i = 0; known[i].name; i++)
        if (known[i].port == p) return known[i].name;
    return (const char *)0;
}

static const char *detect_service(const unsigned char *b, int len) {
    if (!b || len <= 0) return (const char *)0;
    if (len >= 4 && b[0]=='S' && b[1]=='S' && b[2]=='H' && b[3]=='-')    return "SSH";
    if (len >= 5 && b[0]=='H' && b[1]=='T' && b[2]=='T' && b[3]=='P' && b[4]=='/') return "HTTP";
    if (len >= 6 && (AxStrncmp((const char*)b,"<html>",6)==0||AxStrncmp((const char*)b,"<HTML>",6)==0)) return "HTTP";
    if (len >= 9 && AxStrncmp((const char*)b,"<!DOCTYPE",9)==0) return "HTTP";
    if (len >= 14 && AxStrncmp((const char*)b,"<!doctype html",14)==0) return "HTTP";
    if (len >= 3 && (b[0]==0x16||b[0]==0x15) && b[1]==0x03 && b[2]<=0x04) return "TLS/SSL";
    if (len >= 4 && b[0]=='2' && b[1]=='2' && b[2]=='0' && (b[3]==' '||b[3]=='-')) {
        if (AxStrstr((const char*)b,"FTP")||AxStrstr((const char*)b,"ftp")||AxStrstr((const char*)b,"vsftpd")) return "FTP";
        if (AxStrstr((const char*)b,"SMTP")||AxStrstr((const char*)b,"smtp")||AxStrstr((const char*)b,"Postfix")) return "SMTP";
        return "FTP/SMTP";
    }
    if (len >= 4 && b[0]=='+' && b[1]=='O' && b[2]=='K')       return "POP3";
    if (len >= 4 && b[0]=='*' && b[1]==' ' && b[2]=='O' && b[3]=='K') return "IMAP";
    if (len >= 5 && AxStrncmp((const char*)b,"-ERR ",5)==0)     return "Redis";
    if (len >= 1 && b[0]=='$')                                   return "Redis";
    if (len >= 4 && b[0]=='R' && b[1]=='F' && b[2]=='B')        return "VNC";
    if (len >= 5 && b[3]==0x00 && b[4]==0x0a)                    return "MySQL";
    if (len >= 8 && b[4]==0xff && b[5]=='S' && b[6]=='M' && b[7]=='B') return "SMB";
    if (len >= 7 && b[0]==0x03 && b[1]==0x00 && b[4]==0xd0)     return "RDP";
    if (len >= 1 && (b[0]=='{' || b[0]=='['))                    return "JSON-API";
    return (const char *)0;
}

static void extract_banner(const unsigned char *raw, int rawlen, char *out, int cap) {
    if (!raw || rawlen <= 0 || !out || cap <= 4) { if (out && cap > 0) out[0]='\0'; return; }
    int o = 0, max = cap - 4;
    for (int i = 0; i < rawlen && o < max; i++) {
        if (raw[i]=='\r' || raw[i]=='\n') break;
        if (raw[i] >= 0x20 && raw[i] <= 0x7E) out[o++] = (char)raw[i];
    }
    if (o >= max && rawlen > o) { out[o++]='.'; out[o++]='.'; out[o++]='.'; }
    out[o] = '\0';
}

/* ── Non-blocking connect with hard timeout via poll ── */

static int nb_connect(int sock, struct ax_sockaddr_in *addr, int timeout_ms) {
    /* Set non-blocking */
    int flags = AxFcntl(sock, AX_F_GETFL, 0);
    if (flags < 0) flags = 0;
    AxFcntl(sock, AX_F_SETFL, flags | AX_O_NONBLOCK);

    int rc = AxConnect(sock, addr, sizeof(struct ax_sockaddr_in));
    if (rc == 0) {
        /* Connected immediately (localhost etc) */
        AxFcntl(sock, AX_F_SETFL, flags); /* restore blocking */
        return PS_OPEN;
    }

    int err = AxGetErrno();
    if (err != AX_EINPROGRESS) {
        AxFcntl(sock, AX_F_SETFL, flags);
        if (err == AX_ECONNREFUSED) return PS_CLOSED;
        if (err == AX_EHOSTUNREACH || err == AX_ENETUNREACH) return PS_ERROR;
        return PS_CLOSED;
    }

    /* Wait for connect with hard timeout */
    struct ax_pollfd pfd;
    pfd.fd = sock;
    pfd.events = AX_POLLOUT;
    pfd.revents = 0;

    int pr = AxPoll(&pfd, 1, timeout_ms);

    if (pr <= 0) {
        /* Timeout or error → filtered */
        AxFcntl(sock, AX_F_SETFL, flags);
        return PS_FILTERED;
    }

    /* Check SO_ERROR */
    int so_error = 0;
    int elen = 4;
    AxGetsockopt(sock, AX_SOL_SOCKET, AX_SO_ERROR, &so_error, &elen);

    AxFcntl(sock, AX_F_SETFL, flags); /* restore blocking */

    if (so_error == 0) return PS_OPEN;
    if (so_error == AX_ECONNREFUSED) return PS_CLOSED;
    return PS_FILTERED;
}

/* ── Scan one port ── */

static int scan_port(const char *host, int port, char *svc, int svc_cap,
                     char *banner, int banner_cap) {
    svc[0] = '\0';
    banner[0] = '\0';

    int sock = AxSocket(AX_AF_INET, AX_SOCK_STREAM, 0);
    if (sock < 0) return PS_ERROR;

    struct ax_sockaddr_in addr;
    AxMemset(&addr, 0, sizeof(addr));
    addr.sin_family = AX_AF_INET;
    addr.sin_port = AxHtons((unsigned short)port);
    AxInetPton(AX_AF_INET, host, &addr.sin_addr);

    int state = nb_connect(sock, &addr, CONNECT_TIMEOUT_MS);
    if (state != PS_OPEN) {
        AxClose(sock);
        return state;
    }

    /* === Phase 1: passive banner === */
    struct ax_timeval rtv = {BANNER_TIMEOUT_S, 0};
    AxSetsockopt(sock, AX_SOL_SOCKET, AX_SO_RCVTIMEO, &rtv, sizeof(rtv));

    unsigned char buf[512];
    AxMemset(buf, 0, sizeof(buf));
    int blen = AxRecv(sock, buf, sizeof(buf) - 1, 0);

    if (blen > 0) {
        buf[blen] = '\0';
        const char *s = detect_service(buf, blen);
        if (s) AxStrncpy(svc, s, svc_cap - 1);
        extract_banner(buf, blen, banner, banner_cap);
        AxClose(sock);
        if (!svc[0]) {
            const char *kn = port_lookup(port);
            if (kn) AxStrncpy(svc, kn, svc_cap - 1);
            else    AxStrcpy(svc, "unknown");
        }
        return PS_OPEN;
    }

    /* === Phase 2: HTTP probe === */
    const char *probe = "HEAD / HTTP/1.0\r\nHost: t\r\nConnection: close\r\n\r\n";
    AxSend(sock, probe, AxStrlen(probe), 0);
    AxMemset(buf, 0, sizeof(buf));
    blen = AxRecv(sock, buf, sizeof(buf) - 1, 0);
    AxClose(sock);

    if (blen > 0) {
        buf[blen] = '\0';
        const char *s = detect_service(buf, blen);
        if (s) AxStrncpy(svc, s, svc_cap - 1);
        else {
            const char *kn = port_lookup(port);
            if (kn) AxStrncpy(svc, kn, svc_cap - 1);
            else    AxStrcpy(svc, "unknown");
        }
        extract_banner(buf, blen, banner, banner_cap);
        return PS_OPEN;
    }

    const char *kn = port_lookup(port);
    if (kn) AxStrncpy(svc, kn, svc_cap - 1);
    else    AxStrcpy(svc, "open");
    return PS_OPEN;
}

static int str_to_int(const char *s) {
    int v = 0; if (!s) return 0;
    while (*s == ' ') s++;
    while (*s >= '0' && *s <= '9') { v = v*10+(*s-'0'); s++; }
    return v;
}
static int valid_port(int p) { return p >= 1 && p <= 65535; }
static const char *state_str(int s) {
    if (s==PS_OPEN) return "OPEN"; if (s==PS_CLOSED) return "CLOSED";
    if (s==PS_FILTERED) return "FILTERED"; return "ERROR";
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    int hl=0, pl=0;
    char *host  = BeaconDataExtract(&parser, &hl);
    char *ports = BeaconDataExtract(&parser, &pl);

    if (!host || hl <= 1 || !ports || pl <= 1) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Usage: portscan <host> <port1,port2,...|start-end>\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 Port Scan: %s\n", host);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-7s %-10s %-14s %s\n",
                 "PORT", "STATE", "SERVICE", "BANNER");
    BeaconPrintf(CALLBACK_OUTPUT,
        "\xe2\x94\x82  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n");

    char portbuf[4096];
    int pbl = AxStrlen(ports); if (pbl>4095) pbl=4095;
    AxMemcpy(portbuf, ports, pbl); portbuf[pbl] = '\0';

    int n_open=0, n_closed=0, n_filtered=0, n_scanned=0;
    char *dash = AxStrchr(portbuf, '-');
    int is_range = (dash && !AxStrchr(portbuf, ','));

    if (is_range) {
        *dash = '\0';
        int s = str_to_int(portbuf), e = str_to_int(dash+1);
        if (!valid_port(s)) s=1; if (!valid_port(e)) e=65535;
        if (s>e){int t=s;s=e;e=t;}
        for (int p=s; p<=e; p++) {
            if (should_stop()) {
                BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  [!] Stopped by operator at port %d\n", p);
                break;
            }
            char svc[32], ban[80];
            int st = scan_port(host, p, svc, sizeof(svc), ban, sizeof(ban));
            n_scanned++;
            if (st==PS_OPEN) {
                BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-7d %-10s %-14s %s\n", p,"OPEN",svc,ban);
                n_open++;
            } else if (st==PS_FILTERED) n_filtered++;
            else n_closed++;
        }
    } else {
        char *tok = portbuf;
        while (tok && *tok) {
            char *comma = AxStrchr(tok, ',');
            if (comma) *comma = '\0';
            int p = str_to_int(tok);
            if (valid_port(p)) {
                char svc[32], ban[80];
                int st = scan_port(host, p, svc, sizeof(svc), ban, sizeof(ban));
                n_scanned++;
                if (st==PS_OPEN) {
                    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-7d %-10s %-14s %s\n", p,"OPEN",svc,ban);
                    n_open++;
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %-7d %-10s\n", p, state_str(st));
                    if (st==PS_FILTERED) n_filtered++; else n_closed++;
                }
            }
            tok = comma ? comma+1 : (char*)0;
        }
    }

    char s[128];
    if (n_filtered > 0)
        AxSnprintf(s,sizeof(s),"%d open, %d closed, %d filtered / %d scanned", n_open,n_closed,n_filtered,n_scanned);
    else
        AxSnprintf(s,sizeof(s),"%d open, %d closed / %d scanned", n_open,n_closed,n_scanned);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s);
}
