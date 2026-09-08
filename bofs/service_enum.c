/// service_enum.c — Enumerate services: listening ports, daemons, systemd units
/// gcc -c -o service_enum.o service_enum.c -include bof_api.h -Os -fPIC
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
static int hex4(const char *s){int v=0;for(int i=0;i<4&&s[i];i++){int n=0;char c=s[i];
    if(c>='0'&&c<='9')n=c-'0';else if(c>='A'&&c<='F')n=c-'A'+10;else if(c>='a'&&c<='f')n=c-'a'+10;
    v=(v<<4)|n;}return v;}

static void listeners(void) {
    sub("Listening Ports");
    BeaconPrintf(CALLBACK_OUTPUT,"\xe2\x94\x82  %-6s %-22s\n","PROTO","ADDRESS");
    const char *files[]={"/proc/net/tcp","/proc/net/udp",(const char*)0};
    const char *protos[]={"tcp","udp"};
    for(int fi=0;files[fi];fi++){
        char *d=(char*)0;int dl=AxReadFileToBuffer(files[fi],&d,524288);
        if(dl<=0||!d)continue;
        char *line=d;int ln_n=0;
        while(line<d+dl){char *eol=line;while(eol<d+dl&&*eol!='\n')eol++;
            ln_n++;
            if(ln_n>1){
                int is_listen = (fi==1) || (AxStrstr(line," 0A ")!=0); /* UDP always, TCP only LISTEN */
                if(is_listen){
                    char *c1=AxStrchr(line,':');
                    if(c1&&c1<eol){char *loc=c1+2;char *lc=AxStrchr(loc,':');
                        if(lc&&lc<eol){
                            char ih[16];int il=(int)(lc-loc);if(il>15)il=15;AxMemcpy(ih,loc,il);ih[il]='\0';
                            int port=hex4(lc+1);
                            if(port>0||fi==0){
                                unsigned int ip=0;
                                for(int i=0;i<8&&ih[i];i++){int n=0;char c=ih[i];
                                    if(c>='0'&&c<='9')n=c-'0';else if(c>='A'&&c<='F')n=c-'A'+10;
                                    else if(c>='a'&&c<='f')n=c-'a'+10;ip=(ip<<4)|n;}
                                char b[64];AxSnprintf(b,sizeof(b),"%d.%d.%d.%d:%d",
                                    ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF,port);
                                BeaconPrintf(CALLBACK_OUTPUT,"\xe2\x94\x82  %-6s %-22s\n",protos[fi],b);
                            }
                        }
                    }
                }
            }
            line=eol+1;
        }
        AxFree(d);
    }
}

static void daemons(void) {
    sub("Root Daemons (ppid<=1)");
    int dfd=AxOpenDir("/proc"); if(dfd<0)return;
    char db[8192]; int count=0;
    while(1){int nr=AxReadDir(dfd,db,sizeof(db));if(nr<=0)break;
        int p=0;while(p<nr){struct linux_dirent64*e=(struct linux_dirent64*)(db+p);
            if(e->d_type==DT_DIR&&is_num(e->d_name[0])){int pid=atoi_(e->d_name);
                if(pid>0){char path[128];AxSnprintf(path,sizeof(path),"/proc/%d/status",pid);
                    char *st=(char*)0;int sl=AxReadFileToBuffer(path,&st,4096);
                    if(sl>0&&st){
                        char *ul=AxStrstr(st,"Uid:\t");int uid=ul?atoi_(ul+5):-1;
                        if(uid==0){
                            char *nl=AxStrstr(st,"Name:\t");char nm[64]="?";
                            if(nl){nl+=6;char *ne=AxStrchr(nl,'\n');if(ne){int l=(int)(ne-nl);if(l>63)l=63;AxMemcpy(nm,nl,l);nm[l]='\0';}}
                            char *pl=AxStrstr(st,"PPid:\t");int ppid=pl?atoi_(pl+6):99;
                            if(ppid<=1){char b[80];AxSnprintf(b,sizeof(b),"PID %-6d %s",pid,nm);ln(b);count++;}
                        }
                        AxFree(st);
                    }
                }
            }
            p+=e->d_reclen;
        }
    }
    AxCloseFile(dfd);
    char s[32];AxSnprintf(s,sizeof(s),"%d daemons",count);ln(s);
}

static void units(void) {
    sub("Systemd Service Units");
    const char *dirs[]={"/etc/systemd/system","/usr/lib/systemd/system","/lib/systemd/system",(const char*)0};
    for(int di=0;dirs[di];di++){
        int dfd=AxOpenDir(dirs[di]);if(dfd<0)continue;
        char db[8192]; int count=0;
        while(1){int nr=AxReadDir(dfd,db,sizeof(db));if(nr<=0)break;
            int p=0;while(p<nr){struct linux_dirent64*e=(struct linux_dirent64*)(db+p);
                int nl=AxStrlen(e->d_name);
                if(nl>8&&AxStrcmp(e->d_name+nl-8,".service")==0){
                    if(count==0){char b[256];AxSnprintf(b,sizeof(b),"[%s]",dirs[di]);ln(b);}
                    char b[256];AxSnprintf(b,sizeof(b),"  %s",e->d_name);ln(b);count++;}
                p+=e->d_reclen;}}
        AxCloseFile(dfd);
    }
}

void go(char *args, int args_len) {
    hdr("Service Enumeration");
    listeners();
    daemons();
    units();
    fin("Service enumeration complete");
}
