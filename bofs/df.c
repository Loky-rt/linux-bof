#include "bof_api.h"

static int parse_mount_line(const char *line, char *dev, char *mnt, char *type) {
    int i = 0, j = 0;

    while (line[i] == ' ') i++;

    j = 0;
    while (line[i] && line[i] != ' ' && line[i] != '\t' && j < 255) {
        dev[j++] = line[i++];
    }
    dev[j] = '\0';
    if (j == 0) return -1;

    while (line[i] == ' ' || line[i] == '\t') i++;

    j = 0;
    while (line[i] && line[i] != ' ' && line[i] != '\t' && j < 255) {
        mnt[j++] = line[i++];
    }
    mnt[j] = '\0';
    if (j == 0) return -1;

    while (line[i] == ' ' || line[i] == '\t') i++;

    j = 0;
    while (line[i] && line[i] != ' ' && line[i] != '\t' && j < 63) {
        type[j++] = line[i++];
    }
    type[j] = '\0';

    return 0;
}

static int is_virtual_type(const char *type, const char *dev, const char *mnt) {
    const char *virtual_types[] = {
        "proc", "sysfs", "tmpfs", "devtmpfs", "devpts",
        "cgroup", "cgroup2", "securityfs", "debugfs",
        "tracefs", "pstore", "bpf", "hugetlbfs", "mqueue",
        "binfmt_misc", "fuse", "fusectl", "configfs",
        "efivarfs", "overlay", "ramfs", "rootfs", "nsfs",
        "rpc_pipefs", "gvfsd-fuse", "portal", "fuse.gvfsd-fuse",
        "sunrpc", "none", "systemd-1",
        NULL
    };
    for (int i = 0; virtual_types[i]; i++) {
        if (AxStrcmp(type, virtual_types[i]) == 0) {
            return 1;
        }
    }
    if (AxStrstr(dev, "systemd") == dev) return 1;
    if (AxStrstr(mnt, "gvfs") != NULL) return 1;
    if (AxStrstr(mnt, "doc") != NULL) return 1;
    if (AxStrstr(mnt, "rpc_pipefs") != NULL) return 1;

    return 0;
}

static unsigned long to_1k_blocks(unsigned long blocks, unsigned long frsize) {
    return (blocks * frsize) / 1024;
}

static void format_size(unsigned long blocks_1k, char *buf, int cap) {
    unsigned long bytes = blocks_1k * 1024;

    if (bytes >= 1024 * 1024 * 1024) {
        AxSnprintf(buf, cap, "%.1fG", (double)bytes / (1024 * 1024 * 1024));
    } else if (bytes >= 1024 * 1024) {
        AxSnprintf(buf, cap, "%.1fM", (double)bytes / (1024 * 1024));
    } else if (bytes >= 1024) {
        AxSnprintf(buf, cap, "%.1fK", (double)bytes / 1024);
    } else {
        AxSnprintf(buf, cap, "%luB", bytes);
    }
}

void go(char *args, int args_len) {
    (void)args;
    (void)args_len;

    char *mounts = NULL;
    int len = AxReadFileToBuffer("/proc/mounts", &mounts, 65536);

    if (len <= 0 || !mounts) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to read /proc/mounts\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-12s %-12s %-12s %-8s %-15s\n",
                 "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on");
    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-12s %-12s %-12s %-8s %-15s\n",
                 "----------", "----", "----", "-----", "----", "----------");

    char *line = mounts;
    int pos = 0;

    while (pos < len) {
        char *start = line + pos;
        char *end = start;

        while (end < mounts + len && *end != '\n') end++;
        *end = '\0';

        char dev[256] = {0}, mnt[256] = {0}, type[64] = {0};

        if (parse_mount_line(start, dev, mnt, type) == 0) {

            if (is_virtual_type(type, dev, mnt)) {
                pos = (end - mounts) + 1;
                continue;
            }

            struct statvfs st;
            if (AxStatvfs(mnt, &st) == 0) {
                unsigned long total_1k = to_1k_blocks(st.f_blocks, st.f_frsize);
                unsigned long free_1k = to_1k_blocks(st.f_bfree, st.f_frsize);
                unsigned long avail_1k = to_1k_blocks(st.f_bavail, st.f_frsize);
                unsigned long used_1k = total_1k - free_1k;
                int percent = 0;
                if (used_1k + avail_1k > 0) {
                    percent = (int)((used_1k * 100) / (used_1k + avail_1k));
                }

                if (total_1k == 0) {
                    pos = (end - mounts) + 1;
                    continue;
                }

                char size_str[16], used_str[16], avail_str[16];

                format_size(total_1k, size_str, sizeof(size_str));
                format_size(used_1k, used_str, sizeof(used_str));
                format_size(avail_1k, avail_str, sizeof(avail_str));

                BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-12s %-12s %-12s %-8d%% %-15s\n",
                             dev, size_str, used_str, avail_str, percent, mnt);
            }
        }

        pos = (end - mounts) + 1;
    }

    AxFree(mounts);
}
