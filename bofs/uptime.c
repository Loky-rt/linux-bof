#include "bof_api.h"

void go(char *args, int args_len) {
    (void)args;
    (void)args_len;

    struct sysinfo info;

    if (AxSysinfo(&info) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Error getting system information\n");
        return;
    }

    long uptime = info.uptime;
    int days    = (int)(uptime / 86400);
    int hours   = (int)((uptime % 86400) / 3600);
    int minutes = (int)((uptime % 3600) / 60);
    int seconds = (int)(uptime % 60);

    BeaconPrintf(CALLBACK_OUTPUT, "====================[Uptime]====================\n[+] System Uptime: %d days, %d hours, %d minutes, %d seconds\n",
                 days, hours, minutes, seconds);

    // Additional system info
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Load averages: %lu.%02lu %lu.%02lu %lu.%02lu\n",
                 (unsigned long)info.loads[0] / 65536, ((unsigned long)info.loads[0] * 100 / 65536) % 100,
                 (unsigned long)info.loads[1] / 65536, ((unsigned long)info.loads[1] * 100 / 65536) % 100,
                 (unsigned long)info.loads[2] / 65536, ((unsigned long)info.loads[2] * 100 / 65536) % 100);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Total RAM: %lu MB\n", (unsigned long)(info.totalram / 1024 / 1024));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Free RAM: %lu MB\n", (unsigned long)(info.freeram / 1024 / 1024));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Total swap: %lu MB\n", (unsigned long)(info.totalswap / 1024 / 1024));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Processes: %u\n", info.procs);
}
