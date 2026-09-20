#include "bof_api.h"

#ifndef EINTR
#define EINTR     4
#endif
#ifndef ENOENT
#define ENOENT    2
#endif
#ifndef EXDEV
#define EXDEV     18
#endif

#ifndef AT_FDCWD
#define AT_FDCWD  (-100)
#endif

#ifndef O_RDONLY
#define O_RDONLY  0
#endif
#ifndef O_WRONLY
#define O_WRONLY  1
#endif
#ifndef O_CREAT
#define O_CREAT   0100
#endif
#ifndef O_TRUNC
#define O_TRUNC   01000
#endif

#ifndef S_IFMT
#define S_IFMT    0170000
#endif
#ifndef S_IFDIR
#define S_IFDIR   0040000
#endif

extern int   LIBC$rename(const char *oldpath, const char *newpath);
extern int   LIBC$access(const char *path, int mode);
extern char *LIBC$strerror(int errnum);
extern int   LIBC$open(const char *path, int flags, int mode);
extern int   LIBC$close(int fd);
extern long  LIBC$read(int fd, void *buf, long count);
extern long  LIBC$write(int fd, const void *buf, long count);
extern int   LIBC$unlink(const char *path);
extern int   LIBC$stat(const char *path, void *buf);
extern int   LIBC$fchmodat(int dirfd, const char *path, unsigned int mode, int flags);
extern int  *LIBC$__errno_location(void);
extern void *LIBC$malloc(unsigned long size);
extern void  LIBC$free(void *ptr);

static int  bof_errno(void)      { return *LIBC$__errno_location(); }
static void bof_set_errno(int e) { *LIBC$__errno_location() = e; }

static long bof_read(int fd, void *buf, long count) {
    long n;
    do { n = LIBC$read(fd, buf, count); } while (n < 0 && bof_errno() == EINTR);
    return n;
}

static long bof_write(int fd, const void *buf, long count) {
    long n;
    do { n = LIBC$write(fd, buf, count); } while (n < 0 && bof_errno() == EINTR);
    return n;
}

static int bof_strlen(const char *s) {
    int n = 0;
    while (s && s[n]) n++;
    return n;
}

static char *bof_strrchr(const char *s, int c) {
    const char *last = (void*)0;
    if (!s) return (void*)0;
    while (*s) {
        if ((unsigned char)*s == (unsigned char)c) last = s;
        s++;
    }
    return (char *)last;
}

static int bof_strncmp(const char *a, const char *b, int n) {
    while (n-- > 0) {
        if ((unsigned char)*a != (unsigned char)*b)
            return (unsigned char)*a - (unsigned char)*b;
        if (!*a) return 0;
        a++; b++;
    }
    return 0;
}

static char *bof_strncpy(char *dst, const char *src, int n) {
    if (n <= 0) return dst;
    int i = 0;
    while (i < n - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
    return dst;
}

static char *bof_strcat(char *dst, const char *src) {
    char *p = dst;
    while (*p) p++;
    while (*src) *p++ = *src++;
    *p = '\0';
    return dst;
}

static void bof_memset(void *s, int c, int n) {
    unsigned char *p = s;
    while (n-- > 0) *p++ = (unsigned char)c;
}

#if defined(__x86_64__)
  #define STAT_BUF_SIZE  144
  #define STAT_MODE_OFF  24
#elif defined(__aarch64__)
  #define STAT_BUF_SIZE  128
  #define STAT_MODE_OFF  16
#else
  #define STAT_BUF_SIZE  256
  #define STAT_MODE_OFF  24
#endif

static unsigned int stat_mode(const unsigned char *st) {
    unsigned int m;
    __builtin_memcpy(&m, st + STAT_MODE_OFF, sizeof(m));
    return m;
}

static int is_dir(const char *path) {
    unsigned char st[STAT_BUF_SIZE];
    if (LIBC$stat(path, st) != 0) return 0;
    return (stat_mode(st) & S_IFMT) == S_IFDIR;
}

static int same_dir(const char *src, const char *dst) {
    const char *s = bof_strrchr(src, '/');
    const char *d = bof_strrchr(dst, '/');
    if (!s && !d) return 1;
    if (!s || !d) return 0;
    int slen = (int)(s - src);
    int dlen = (int)(d - dst);
    if (slen != dlen) return 0;
    return bof_strncmp(src, dst, slen) == 0;
}

static int copy_and_delete(const char *src, const char *dst) {
    unsigned char st[STAT_BUF_SIZE];
    if (LIBC$stat(src, st) != 0) return -1;
    unsigned int src_mode = stat_mode(st) & 07777;

    int src_fd = LIBC$open(src, O_RDONLY, 0);
    if (src_fd < 0) return -1;

    int dst_fd = LIBC$open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        LIBC$close(src_fd);
        return -1;
    }

    char  buf[4096];
    long  n;
    int   ok = 1;

    while ((n = bof_read(src_fd, buf, sizeof(buf))) > 0) {
        long off = 0;
        while (off < n) {
            long w = bof_write(dst_fd, buf + off, n - off);
            if (w <= 0) { ok = 0; break; }
            off += w;
        }
        if (!ok) break;
    }
    if (n < 0) ok = 0;

    LIBC$close(src_fd);
    LIBC$close(dst_fd);

    if (!ok) {
        LIBC$unlink(dst);
        return -1;
    }

    LIBC$fchmodat(AT_FDCWD, dst, src_mode, 0);

    return LIBC$unlink(src);
}

static char *build_dst(const char *src, const char *dst_raw) {
    const char *base = bof_strrchr(src, '/');
    base = base ? base + 1 : src;
    int base_len = bof_strlen(base);
    int dst_len  = bof_strlen(dst_raw);

    if (is_dir(dst_raw)) {
        int need_slash = (dst_len > 0 && dst_raw[dst_len - 1] != '/') ? 1 : 0;
        int total      = dst_len + need_slash + base_len + 1;

        char *out = (char *)LIBC$malloc((unsigned long)total);
        if (!out) return (void*)0;

        int p = 0;
        for (int i = 0; i < dst_len; i++) out[p++] = dst_raw[i];
        if (need_slash) out[p++] = '/';
        for (int i = 0; i < base_len; i++) out[p++] = base[i];
        out[p] = '\0';
        return out;
    }

    char *out = (char *)LIBC$malloc((unsigned long)(dst_len + 1));
    if (!out) return (void*)0;
    for (int i = 0; i < dst_len; i++) out[i] = dst_raw[i];
    out[dst_len] = '\0';
    return out;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int   src_len = 0;
    char *src     = BeaconDataExtract(&parser, &src_len);
    if (!src || src_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "mv: missing source path\n");
        return;
    }

    int   dst_len = 0;
    char *dst_raw = BeaconDataExtract(&parser, &dst_len);
    if (!dst_raw || dst_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "mv: missing destination path\n");
        return;
    }

    if (LIBC$access(src, 0) != 0) {
        int err = bof_errno();
        BeaconPrintf(CALLBACK_ERROR,
                     "mv: cannot access '%s': %s\n", src, LIBC$strerror(err));
        return;
    }

    char *dst_buf = build_dst(src, dst_raw);
    if (!dst_buf) {
        BeaconPrintf(CALLBACK_ERROR, "mv: out of memory\n");
        return;
    }

    if (LIBC$rename(src, dst_buf) == 0) {
        if (same_dir(src, dst_buf))
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] renamed '%s' -> '%s'\n", src, dst_buf);
        else
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] moved '%s' -> '%s'\n", src, dst_buf);
        LIBC$free(dst_buf);
        return;
    }

    int err = bof_errno();

    if (err == EXDEV) {
        bof_set_errno(0);
        int r = copy_and_delete(src, dst_buf);
        if (r == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] moved '%s' -> '%s' (cross-device copy)\n",
                         src, dst_buf);
        } else {
            int e2 = bof_errno();
            BeaconPrintf(CALLBACK_ERROR,
                         "mv: cannot move '%s' to '%s': %s\n",
                         src, dst_buf, LIBC$strerror(e2 ? e2 : err));
        }
        LIBC$free(dst_buf);
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "mv: cannot move '%s' to '%s': %s\n",
                 src, dst_buf, LIBC$strerror(err));
    LIBC$free(dst_buf);
}
