#include "bof_api.h"

/* DLR declarations */

extern int   LIBC$rename(const char *oldpath, const char *newpath);
extern void *LIBC$opendir(const char *path);
extern int   LIBC$closedir(void *dir);
extern int  *LIBC$__errno_location(void);
extern int   LIBC$access(const char *path, int mode);
extern char *LIBC$strerror(int errnum);
extern int   LIBC$open(const char *path, int flags, int mode);
extern int   LIBC$close(int fd);
extern long  LIBC$read(int fd, void *buf, long count);
extern long  LIBC$write(int fd, const void *buf, long count);
extern int   LIBC$unlink(const char *path);

/* Portable string helpers (no LIBC$ IFUNCs)  */
/* x86_64 glibc exports strlen/strcpy/strcat as IFUNC resolvers in .gnu_hash
 * The runtime resolver returns the IFUNC trampoline, not the real impl
 * Calling it causes a crash or silent wrong result. Use inline versions
 * This BOF is developed without using Ax* wrappers to demonstrate the operation of dynamic libc resolution
*/

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
    while (n--) *p++ = (unsigned char)c;
}

#define O_RDONLY     0
#define O_WRONLY     1
#define O_CREAT      0100
#define O_TRUNC      01000
#define EXDEV        18

static int is_dir(const char *path) {
    void *dir = LIBC$opendir(path);
    if (!dir) return 0;
    LIBC$closedir(dir);
    return 1;
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
    int src_fd = LIBC$open(src, O_RDONLY, 0);
    if (src_fd < 0) return -1;

    int dst_fd = LIBC$open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        LIBC$close(src_fd);
        return -1;
    }

    char buf[4096];
    long n;
    while ((n = LIBC$read(src_fd, buf, sizeof(buf))) > 0) {
        long written = LIBC$write(dst_fd, buf, n);
        if (written != n) {
            LIBC$close(src_fd);
            LIBC$close(dst_fd);
            LIBC$unlink(dst);
            return -1;
        }
    }

    LIBC$close(src_fd);
    LIBC$close(dst_fd);

    if (n < 0) {
        LIBC$unlink(dst);
        return -1;
    }

    return LIBC$unlink(src);
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
        BeaconPrintf(CALLBACK_ERROR,
                     "mv: cannot access '%s': No such file or directory\n", src);
        return;
    }

    char dst_buf[1024];
    bof_memset(dst_buf, 0, sizeof(dst_buf));

    if (is_dir(dst_raw)) {
        char *base = bof_strrchr(src, '/');
        base = base ? base + 1 : src;

        bof_strncpy(dst_buf, dst_raw, sizeof(dst_buf) - 1);
        int dlen = bof_strlen(dst_buf);
        if (dlen > 0 && dst_buf[dlen - 1] != '/') {
            dst_buf[dlen]     = '/';
            dst_buf[dlen + 1] = '\0';
        }
        bof_strcat(dst_buf, base);
    } else {
        bof_strncpy(dst_buf, dst_raw, sizeof(dst_buf) - 1);
    }

    if (LIBC$rename(src, dst_buf) == 0) {
        if (same_dir(src, dst_buf))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] renamed '%s' -> '%s'\n", src, dst_buf);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[+] moved '%s' -> '%s'\n", src, dst_buf);
        return;
    }

    int err = *LIBC$__errno_location();

    if (err == EXDEV) {
        if (copy_and_delete(src, dst_buf) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] moved '%s' -> '%s' (cross-device copy)\n", src, dst_buf);
        } else {
            err = *LIBC$__errno_location();
            BeaconPrintf(CALLBACK_ERROR,
                         "mv: cannot move '%s' to '%s': %s\n",
                         src, dst_buf, LIBC$strerror(err));
        }
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "mv: cannot move '%s' to '%s': %s\n",
                 src, dst_buf, LIBC$strerror(err));
}
