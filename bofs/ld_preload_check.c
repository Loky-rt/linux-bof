/// ld_preload_check.c — LD_PRELOAD / shared library hook analysis
/// gcc -c -o ld_preload_check.o ld_preload_check.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

struct linux_dirent64 {
    unsigned long long d_ino; long long d_off;
    unsigned short d_reclen; unsigned char d_type; char d_name[];
};
#define DT_DIR 4

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }
static int is_num(char c){return c>='0'&&c<='9';}
static int atoi_(const char *s){int v=0;while(*s>='0'&&*s<='9'){v=v*10+(*s-'0');s++;}return v;}

static void check_env(void) {
    sub("LD_PRELOAD in current process");
    char v[1024];
    if(AxGetEnv("LD_PRELOAD",v,sizeof(v))>0){
        char b[1100];AxSnprintf(b,sizeof(b),"[!!] LD_PRELOAD=%s",v);ln(b);}
    else ln("[-] Not set");
}

static void scan_procs(void) {
    sub("Scanning processes for LD_PRELOAD");
    int dfd=AxOpenDir("/proc"); if(dfd<0)return;
    int found=0; char db[8192];
    while(1){int nr=AxReadDir(dfd,db,sizeof(db));if(nr<=0)break;
        int p=0;while(p<nr){struct linux_dirent64*e=(struct linux_dirent64*)(db+p);
            if(e->d_type==DT_DIR&&is_num(e->d_name[0])){int pid=atoi_(e->d_name);
                if(pid>0){char path[128];AxSnprintf(path,sizeof(path),"/proc/%d/environ",pid);
                    char *env=(char*)0;int el=AxReadFileToBuffer(path,&env,65536);
                    if(el>0&&env){int ep=0;while(ep<el){char *en=env+ep;int enl=0;
                        while(ep+enl<el&&en[enl]!='\0')enl++;
                        if(enl>11&&AxStrncmp(en,"LD_PRELOAD=",11)==0){
                            char nm[64]="?";char sp[128];AxSnprintf(sp,sizeof(sp),"/proc/%d/comm",pid);
                            char *cm=(char*)0;int cl=AxReadFileToBuffer(sp,&cm,64);
                            if(cl>0&&cm){if(cm[cl-1]=='\n')cm[cl-1]='\0';AxStrcpy(nm,cm);AxFree(cm);}
                            char pv[512];int vl=enl-11;if(vl>511)vl=511;AxMemcpy(pv,en+11,vl);pv[vl]='\0';
                            char b[600];AxSnprintf(b,sizeof(b),"[!!] PID %-6d (%s): %s",pid,nm,pv);ln(b);
                            found++;break;}
                        ep+=enl+1;}AxFree(env);}}}
            p+=e->d_reclen;}}
    AxCloseFile(dfd);
    if(!found) ln("[-] No processes with LD_PRELOAD");
}

static void check_preload_file(void) {
    sub("/etc/ld.so.preload");
    char *d=(char*)0;int dl=AxReadFileToBuffer("/etc/ld.so.preload",&d,8192);
    if(dl>0&&d){
        ln("[!!] /etc/ld.so.preload EXISTS — global preload active");
        char *line=d;while(line<d+dl){char *eol=line;while(eol<d+dl&&*eol!='\n')eol++;
            int ll=(int)(eol-line);if(ll>0&&line[0]!='#'){
                char b[512];if(ll>511)ll=511;AxMemcpy(b,line,ll);b[ll]='\0';
                unsigned int m=0;long fs=0;
                int ex=AxFileStat(b,&m,&fs,(unsigned int*)0,(unsigned int*)0)==0;
                char b2[600];AxSnprintf(b2,sizeof(b2),"%s (%s, %ld B)",b,ex?"exists":"MISSING",fs);ln(b2);
            }line=eol+1;}
        AxFree(d);
    } else ln("[-] Does not exist (normal)");
}

static void check_lib_dirs(void) {
    sub("Writable Library Directories");
    const char *dirs[]={"/lib","/lib64","/usr/lib","/usr/lib64","/usr/local/lib",(const char*)0};
    int found=0;
    for(int i=0;dirs[i];i++){unsigned int m=0;
        if(AxFileStat(dirs[i],&m,(long*)0,(unsigned int*)0,(unsigned int*)0)==0&&(m&002)){
            char b[128];AxSnprintf(b,sizeof(b),"[!!] %s is world-writable",dirs[i]);ln(b);found++;}}
    if(!found) ln("[-] All standard lib dirs properly protected");
}

void go(char *args, int args_len) {
    hdr("LD_PRELOAD / Library Hook Analysis");
    check_env();
    scan_procs();
    check_preload_file();

    sub("LD_LIBRARY_PATH");
    char v[2048];
    if(AxGetEnv("LD_LIBRARY_PATH",v,sizeof(v))>0){
        char b[2100];AxSnprintf(b,sizeof(b),"[!] LD_LIBRARY_PATH=%s",v);ln(b);
    } else ln("[-] Not set");

    check_lib_dirs();
    fin("LD analysis complete");
}
