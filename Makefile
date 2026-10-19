BOF_CFLAGS = -Os -ffunction-sections -fdata-sections -fno-unwind-tables \
             -fno-asynchronous-unwind-tables \
             -fno-ident -fno-builtin -fno-common -g0 \
             -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable -ffreestanding

BOF_CFLAGS_ARM64 = -mno-outline-atomics -fPIC

BOF_INCLUDE = -I include

all: bof

bof: clean
	@(mkdir bofs_compile 2>/dev/null) && echo 'creating bofs_compile directory' || echo 'bofs_compile directory exists'

	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/service_enum.x64.o bofs/service_enum.c) && echo '[+] service_enum' || echo '[!] service_enum'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/container_detect.x64.o bofs/container_detect.c) && echo '[+] container_detect' || echo '[!] container_detect'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/host_recon.x64.o bofs/host_recon.c) && echo '[+] host_recon' || echo '[!] host_recon'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/ld_preload_check.x64.o bofs/ld_preload_check.c) && echo '[+] ld_preload_check' || echo '[!] ld_preload_check'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/proc_enum.x64.o bofs/proc_enum.c) && echo '[+] proc_enum' || echo '[!] proc_enum'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/shadow_dump.x64.o bofs/shadow_dump.c) && echo '[+] shadow_dump' || echo '[!] shadow_dump'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/sudo_check.x64.o bofs/sudo_check.c) && echo '[+] sudo_check' || echo '[!] sudo_check'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/cred_harvest.x64.o bofs/cred_harvest.c) && echo '[+] cred_harvest' || echo '[!] cred_harvest'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/kernel_exploit_check.x64.o bofs/kernel_exploit_check.c) && echo '[+] kernel_exploit_check' || echo '[!] kernel_exploit_check'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/net_enum.x64.o bofs/net_enum.c) && echo '[+] net_enum' || echo '[!] net_enum'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/ssh_keys.x64.o bofs/ssh_keys.c) && echo '[+] ssh_keys' || echo '[!] ssh_keys'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/suid_scan.x64.o bofs/suid_scan.c) && echo '[+] suid_scan' || echo '[!] suid_scan'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/arp.x64.o bofs/arp.c) && echo '[+] arp' || echo '[!] arp'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/nslookup.x64.o bofs/nslookup.c) && echo '[+] nslookup' || echo '[!] nslookup'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/portscan.x64.o bofs/portscan.c) && echo '[+] portscan' || echo '[!] portscan'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/timestomp.x64.o bofs/timestomp.c) && echo '[+] timestomp' || echo '[!] timestomp'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/keylog_start.x64.o bofs/keylogger_start.c) && echo '[+] keylog_start' || echo '[!] keylog_start'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/keylog_dump.x64.o bofs/keylogger_dump.c) && echo '[+] keylog_dump' || echo '[!] keylog_dump'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/krb.x64.o bofs/krb.c) && echo '[+] klist' || echo '[!] klist'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/persist_cron.x64.o bofs/persist_cron.c) && echo '[+] persist_cron' || echo '[!] persist_cron'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/uptime.x64.o bofs/uptime.c) && echo '[+] uptime' || echo '[!] uptime'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/persist_systemd.x64.o bofs/persist_systemd.c) && echo '[+] persist_systemd' || echo '[!] persist_systemd'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/chmod.x64.o bofs/chmod.c) && echo '[+] chmod' || echo '[!] chmod'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/chown.x64.o bofs/chown.c) && echo '[+] chown' || echo '[!] chown'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/df.x64.o bofs/df.c) && echo '[+] df' || echo '[!] df'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/load_elf.x64.o bofs/load_elf.c) && echo '[+] load_elf' || echo '[!] load_elf'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/mv.x64.o bofs/mv.c) && echo '[+] mv' || echo '[!] mv'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/recon_lb.x64.o bofs/recon_lb.c) && echo '[+] recon_lb' || echo '[!] recon_lb'
	@(gcc -c $(BOF_CFLAGS) $(BOF_INCLUDE) -o bofs_compile/so_inject.x64.o bofs/so_inject.c) && echo '[+] so_inject' || echo '[!] so_inject'
	@echo "Compiling BOFs for ARM64..."
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/service_enum.arm64.o bofs/service_enum.c) && echo '[+] service_enum' || echo '[!] service_enum'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/container_detect.arm64.o bofs/container_detect.c) && echo '[+] container_detect' || echo '[!] container_detect'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/host_recon.arm64.o bofs/host_recon.c) && echo '[+] host_recon' || echo '[!] host_recon'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/ld_preload_check.arm64.o bofs/ld_preload_check.c) && echo '[+] ld_preload_check' || echo '[!] ld_preload_check'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/proc_enum.arm64.o bofs/proc_enum.c) && echo '[+] proc_enum' || echo '[!] proc_enum'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/shadow_dump.arm64.o bofs/shadow_dump.c) && echo '[+] shadow_dump' || echo '[!] shadow_dump'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/sudo_check.arm64.o bofs/sudo_check.c) && echo '[+] sudo_check' || echo '[!] sudo_check'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/cred_harvest.arm64.o bofs/cred_harvest.c) && echo '[+] cred_harvest' || echo '[!] cred_harvest'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/kernel_exploit_check.arm64.o bofs/kernel_exploit_check.c) && echo '[+] kernel_exploit_check' || echo '[!] kernel_exploit_check'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/net_enum.arm64.o bofs/net_enum.c) && echo '[+] net_enum' || echo '[!] net_enum'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/ssh_keys.arm64.o bofs/ssh_keys.c) && echo '[+] ssh_keys' || echo '[!] ssh_keys'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/suid_scan.arm64.o bofs/suid_scan.c) && echo '[+] suid_scan' || echo '[!] suid_scan'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/arp.arm64.o bofs/arp.c) && echo '[+] arp' || echo '[!] arp'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/nslookup.arm64.o bofs/nslookup.c) && echo '[+] nslookup' || echo '[!] nslookup'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/portscan.arm64.o bofs/portscan.c) && echo '[+] portscan' || echo '[!] portscan'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/timestomp.arm64.o bofs/timestomp.c) && echo '[+] timestomp' || echo '[!] timestomp'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/keylog_start.arm64.o bofs/keylogger_start.c) && echo '[+] keylog_start' || echo '[!] keylog_start'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/keylog_dump.arm64.o bofs/keylogger_dump.c) && echo '[+] keylog_dump' || echo '[!] keylog_dump'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/krb.arm64.o bofs/krb.c) && echo '[+] klist' || echo '[!] klist'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/persist_cron.arm64.o bofs/persist_cron.c) && echo '[+] persist_cron' || echo '[!] persist_cron'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/uptime.arm64.o bofs/uptime.c) && echo '[+] uptime' || echo '[!] uptime'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/persist_systemd.arm64.o bofs/persist_systemd.c) && echo '[+] persist_systemd' || echo '[!] persist_systemd'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/chmod.arm64.o bofs/chmod.c) && echo '[+] chmod' || echo '[!] chmod'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/chown.arm64.o bofs/chown.c) && echo '[+] chown' || echo '[!] chown'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/df.arm64.o bofs/df.c) && echo '[+] df' || echo '[!] df'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/load_elf.arm64.o bofs/load_elf.c) && echo '[+] load_elf' || echo '[!] load_elf'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/mv.arm64.o bofs/mv.c) && echo '[+] mv' || echo '[!] mv'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/recon_lb.arm64.o bofs/recon_lb.c) && echo '[+] recon_lb' || echo '[!] recon_lb'
	@(aarch64-linux-gnu-gcc -c $(BOF_CFLAGS) $(BOF_CFLAGS_ARM64) $(BOF_INCLUDE) -o bofs_compile/so_inject.arm64.o bofs/so_inject.c) && echo '[+] so_inject' || echo '[!] so_inject'
clean:
	@(rm -rf bofs_compile)
