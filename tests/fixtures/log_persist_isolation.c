#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <dirent.h>
#include <poll.h>
#define main included_log_monitor_main
#include LOG_MONITOR_SOURCE
#undef main

/* Only the first persistence open is redirected to a full real pipe. */
bool g_persist_all_logs = true;
LogLevel g_min_log_level = LOG_INFO;
void log_internal(LogLevel l, const char* f, ...) { (void)l; (void)f; }
void nsp_comm_post(nsp_ch_t c, const void* p, size_t n) { (void)c; (void)p; (void)n; }
void nsp_log_report(nsp_ch_t c, uint64_t n, void* p) { (void)c; (void)n; (void)p; }
static int sink[2], ready[2], clients[2];
static _Atomic bool first_open = true, main_disk_io, stop_done;
static pthread_t dispatcher_id;
static bool detect_main_io, fail_start, short_write, zero_write;
static unsigned sink_opens, sink_writes;
static int fault_fd = -1;
static _Atomic int io_fd = -1, sys_fd = -1;
extern int __real_open(const char*, int, ...);
int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (!strcmp(path, g_persist_io.path)) {
        sink_opens++;
        if (detect_main_io && pthread_equal(pthread_self(), dispatcher_id)) atomic_store(&main_disk_io, true);
        if (atomic_exchange(&first_open, false)) {
            int fd=dup(sink[1]); assert(fd>=0); atomic_store(&io_fd,fd);
            assert(write(ready[1], "x", 1) == 1);
            return fd;
        }
    }
    int fd = __real_open(path, flags, mode);
    if (!strcmp(path,g_persist_io.path)) {
        atomic_store(&io_fd,fd);
        if (short_write || zero_write) fault_fd=fd;
    }
    if (!strcmp(path,g_persist_sys.path)) atomic_store(&sys_fd,fd);
    return fd;
}
extern ssize_t __real_write(int,const void*,size_t);
ssize_t __wrap_write(int fd,const void* bytes,size_t len) {
    if (detect_main_io && (fd==atomic_load(&io_fd)||fd==atomic_load(&sys_fd)) &&
        pthread_equal(pthread_self(),dispatcher_id)) atomic_store(&main_disk_io,true);
    if (fd==fault_fd && (short_write || zero_write)) {
        sink_writes++;
        if (zero_write) return 0;
        if (sink_writes==1) return __real_write(fd,bytes,len<8?len:8);
        errno=EIO; return -1;
    }
    return __real_write(fd,bytes,len);
}
extern int __real_close(int);
int __wrap_close(int fd) {
    int expected=fd; atomic_compare_exchange_strong(&io_fd,&expected,-1);
    expected=fd; atomic_compare_exchange_strong(&sys_fd,&expected,-1);
    return __real_close(fd); /* do not misclassify a later socket that reuses the disk fd */
}
static bool persist_path(const char* path) {
    return !strcmp(path,g_persist_io.path)||!strcmp(path,g_persist_io.rot)||
           !strcmp(path,g_persist_sys.path)||!strcmp(path,g_persist_sys.rot);
}
extern int __real_unlink(const char*);
int __wrap_unlink(const char* path) {
    if (detect_main_io && persist_path(path) && pthread_equal(pthread_self(),dispatcher_id))
        atomic_store(&main_disk_io,true);
    return __real_unlink(path);
}
extern int __real_rename(const char*,const char*);
int __wrap_rename(const char* old,const char* next) {
    if (detect_main_io && (persist_path(old)||persist_path(next)) &&
        pthread_equal(pthread_self(),dispatcher_id)) atomic_store(&main_disk_io,true);
    return __real_rename(old,next);
}
extern int __real_pthread_create(pthread_t*,const pthread_attr_t*,void* (*)(void*),void*);
int __wrap_pthread_create(pthread_t* tid,const pthread_attr_t* attr,void* (*fn)(void*),void* arg) {
    if (fail_start) return EAGAIN;
    return __real_pthread_create(tid,attr,fn,arg);
}
static int fd_count(void) {
    DIR* d = opendir("/proc/self/fd"); assert(d); int n = 0;
    while (readdir(d)) n++;
    closedir(d); return n;
}
static void stage_rows(unsigned count) {
    char row[MAX_MSG_LEN]; memset(row, 'p', sizeof(row)-1); row[sizeof(row)-1]=0;
    memcpy(row,"PRE_CLEAR_",10);
    for (unsigned i=0; i<count; i++) persist_stage(&g_persist_io,row,LOG_INFO,1700000000);
}
static void* dispatcher(void* unused) {
    (void)unused; dispatcher_id = pthread_self(); stage_rows(64);
    ClientCtx ctx={.fd=clients[0]};
    for (;;) {
        char cmd[32]={0};
        for (size_t i=0;i<sizeof(cmd)-1;i++) { assert(read(clients[0],cmd+i,1)==1); if (!cmd[i]) break; }
        if (!strcmp(cmd,"QUIT")) break;
        if (!strcmp(cmd,"LOAD")) {
            persist_stage(&g_persist_sys,"KEEP_SYS_GATED",LOG_WARN,1700000000);
            stage_rows(512); assert(write(clients[0],"LOADED\n",7)==7);
        }
        else if (!strcmp(cmd,"POST")) { persist_stage(&g_persist_io,"POST_CLEAR",LOG_INFO,1700000001); assert(write(clients[0],"POSTED\n",7)==7); }
        else assert(process_line(&ctx,cmd,NULL,0)==1);
    }
    return NULL;
}
static bool command(const char* cmd, const char* expected, int timeout) {
    assert(write(clients[1],cmd,strlen(cmd)+1)==(ssize_t)strlen(cmd)+1);
    struct pollfd p={.fd=clients[1],.events=POLLIN};
    if (poll(&p,1,timeout)!=1) return false;
    char reply[128]={0}; ssize_t n=read(clients[1],reply,sizeof(reply)-1); assert(n>0);
    if (strcmp(reply,expected)) { fprintf(stderr,"unexpected reply: %s",reply); return false; }
    return true;
}
static void* stop_owner(void* unused) {
    (void)unused;
#ifdef PERSIST_QUEUE_CAP
    persist_worker_stop();
#endif
    atomic_store(&stop_done,true); return NULL;
}
static void init_case(const char* path) {
    init_buf(&g_io_buf,4); init_buf(&g_sys_buf,4); init_buf(&g_logcat_buf,4);
    persist_init_writer(&g_persist_io,"io"); persist_init_writer(&g_persist_sys,"sys");
    snprintf(g_persist_io.path,sizeof(g_persist_io.path),"%s/io.log",path);
    snprintf(g_persist_io.rot,sizeof(g_persist_io.rot),"%s/io.log.1",path);
    snprintf(g_persist_sys.path,sizeof(g_persist_sys.path),"%s/sys.log",path);
    snprintf(g_persist_sys.rot,sizeof(g_persist_sys.rot),"%s/sys.log.1",path);
}
static size_t read_file(const char* path,char* text,size_t cap) {
    FILE* f=fopen(path,"r"); assert(f); size_t n=fread(text,1,cap-1,f); assert(!ferror(f));
    fclose(f); text[n]=0; return n;
}
#ifdef PERSIST_QUEUE_CAP
static int unit_case(const char* path,const char* mode) {
    int before=fd_count(); alarm(6); atomic_store(&first_open,false); init_case(path);
    if (!strcmp(mode,"partial") || !strcmp(mode,"zero")) {
        const char row[]="2023-11-14 22:13:20|INFO|retained-tail\n";
        size_t len=sizeof(row)-1; memcpy(g_persist_io.stage,row,len); g_persist_io.staged=len;
        short_write=!strcmp(mode,"partial"); zero_write=!strcmp(mode,"zero");
        uint64_t flushed_at=persist_now_ms();
        persist_flush(&g_persist_io);
        size_t written=short_write?8:0;
        assert(g_persist_io.staged==len-written);
        assert(!memcmp(g_persist_io.stage,row+written,len-written));
        assert(g_persist_io.fail_until_ms>=flushed_at+PERSIST_FAIL_BACKOFF_MS);
        unsigned attempts=sink_opens;
        persist_flush(&g_persist_io); assert(sink_opens==attempts); /* backoff suppresses open */
        assert(sink_writes==(short_write?2u:1u));
        short_write=zero_write=false; g_persist_io.fail_until_ms=0;
        persist_flush(&g_persist_io); assert(g_persist_io.staged==0);
        char text[128]; assert(read_file(g_persist_io.path,text,sizeof(text))==len);
        assert(!strcmp(text,row)); /* no duplicate prefix, no missing tail */
    } else if (!strcmp(mode,"start-fail")) {
        fail_start=true; assert(!persist_worker_start()); fail_start=false;
        persist_stage(&g_persist_io,"DROP_IO",LOG_INFO,1700000000);
        persist_stage(&g_persist_sys,"DROP_SYS",LOG_INFO,1700000000);
        assert(g_persist_io.dropped==1 && g_persist_sys.dropped==1);
        assert(g_persist_queue.count==0 && sink_opens==0);
        /* Seed actual history after failed start; OK must mean only logical clear. */
        const char history[]="2023-11-14 22:13:20|INFO|DISK_REMAINS\n";
        const char* paths[2]={g_persist_io.path,g_persist_io.rot};
        for(unsigned i=0;i<2;i++) {
            FILE* f=fopen(paths[i],"w");assert(f);
            assert(fwrite(history,1,sizeof(history)-1,f)==sizeof(history)-1);fclose(f);
        }
        disk_load(&g_io_disk,g_persist_io.rot,g_persist_io.path); assert(g_io_disk.count==2);
        push_log(&g_io_buf,"VOLATILE",1,LOG_INFO);assert(g_persist_io.dropped==2);
        unsigned before_clear=sink_opens; dispatcher_id=pthread_self();detect_main_io=true;
        int pair[2]; assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0);
        ClientCtx ctx={.fd=pair[0]}; char reply[64]={0}, count[]="COUNT", clear[]="CLEAR_IO";
        assert(process_line(&ctx,count,NULL,0)==1); assert(read(pair[1],reply,sizeof(reply))>0);
        assert(!strcmp(reply,"COUNT|3|0|0\n"));
        memset(reply,0,sizeof(reply)); assert(process_line(&ctx,clear,NULL,0)==1);
        assert(read(pair[1],reply,sizeof(reply))>0 && !strcmp(reply,"OK\n"));
        memset(reply,0,sizeof(reply)); assert(process_line(&ctx,count,NULL,0)==1);
        assert(read(pair[1],reply,sizeof(reply))>0 && !strcmp(reply,"COUNT|0|0|0\n"));
        assert(!g_io_disk.data && !g_io_disk.strings && !g_io_disk.count);
        persist_lazy_tick(); assert(sink_opens==before_clear && !atomic_load(&main_disk_io));
        detect_main_io=false;
        for(unsigned i=0;i<2;i++) { char text[128];read_file(paths[i],text,sizeof(text));assert(!strcmp(text,history)); }
        close(pair[0]);close(pair[1]);
    } else {
        if (!strcmp(mode,"rotation")) {
            int fd=open(g_persist_io.path,O_CREAT|O_WRONLY|O_CLOEXEC,0600); assert(fd>=0);
            assert(ftruncate(fd,PERSIST_FILE_MAX-8)==0);close(fd);
        }
        assert(persist_worker_start());
        if (!strcmp(mode,"clear")) {
            persist_stage(&g_persist_io,"OLD_IO",LOG_INFO,1700000000);
            persist_stage(&g_persist_sys,"KEEP_SYS",LOG_WARN,1700000000);
            persist_clear(&g_persist_io); persist_clear(&g_persist_io);
            persist_stage(&g_persist_io,"BETWEEN_CLEARS",LOG_INFO,1700000000);
            persist_clear(&g_persist_io);
            persist_stage(&g_persist_io,"NEW_IO",LOG_INFO,1700000000);
        } else if (!strcmp(mode,"lazy")) {
            persist_stage(&g_persist_io,"LAZY",LOG_INFO,1700000000);
            uint64_t start=persist_now_ms(); struct stat st;
            while (stat(g_persist_io.path,&st)<0 || !st.st_size) {
                assert(persist_now_ms()-start<2200); struct pollfd empty={.fd=-1};poll(&empty,0,20);
            }
            assert(persist_now_ms()-start>=800); /* owner has its own 1s lazy deadline */
        } else if (!strcmp(mode,"format")) {
            char long_msg[MAX_MSG_LEN*2]; memset(long_msg,'x',sizeof(long_msg)-1);long_msg[sizeof(long_msg)-1]=0;
            persist_stage(&g_persist_io,"named",LOG_ERROR,1700000000);
            persist_stage(&g_persist_io,"fallback",LOG_IO,1700000001);
            persist_stage(&g_persist_io,long_msg,LOG_INFO,1700000002);
        } else {
            assert(!strcmp(mode,"rotation"));
            persist_stage(&g_persist_io,"ROTATED",LOG_INFO,1700000000);
        }
        persist_worker_stop();
        char text[MAX_MSG_LEN*2]; size_t len=read_file(g_persist_io.path,text,sizeof(text));
        if (!strcmp(mode,"clear")) {
            assert(!strcmp(text,"2023-11-14 22:13:20|INFO|NEW_IO\n"));
            read_file(g_persist_sys.path,text,sizeof(text)); assert(strstr(text,"|WARN|KEEP_SYS\n"));
        } else if (!strcmp(mode,"format")) {
            const char prefix[]="2023-11-14 22:13:20|ERROR|named\n2023-11-14 22:13:21|INFO|fallback\n";
            assert(!strncmp(text,prefix,sizeof(prefix)-1));
            assert(len==sizeof(prefix)-1+PERSIST_LINE_CAP-1 && text[len-1]=='\n');
        } else if (!strcmp(mode,"rotation")) {
            struct stat cur,rot;assert(!stat(g_persist_io.path,&cur)&&!stat(g_persist_io.rot,&rot));
            assert((uint64_t)cur.st_size<=PERSIST_FILE_MAX && rot.st_size==PERSIST_FILE_MAX-8);
            assert(strstr(text,"|INFO|ROTATED\n"));
        }
    }
    if (g_persist_io.stage || g_persist_sys.stage) persist_worker_stop();
    destroy_buf(&g_io_buf);destroy_buf(&g_sys_buf);destroy_buf(&g_logcat_buf);
    int after=fd_count(); assert(before==after); alarm(0);
    printf("PASS %s: fd_before=%d fd_after=%d children=0 owner_joined_or_not_started=1\n",mode,before,after);
    return 0;
}
#endif
int main(int argc, char** argv) {
    assert((argc==2||argc==3) && argv[1][0]=='/');
    setenv("TZ","UTC",1);tzset();
#ifdef PERSIST_QUEUE_CAP
    if (argc==3 && strcmp(argv[2],"isolation")) return unit_case(argv[1],argv[2]);
#endif
    detect_main_io=true; alarm(6); int before=fd_count();
    assert(pipe2(sink,O_CLOEXEC|O_NONBLOCK)==0); assert(pipe2(ready,O_CLOEXEC)==0);
    assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,clients)==0);
    char fill[4096]={0}; ssize_t n; size_t filled=0;
    while ((n=write(sink[1],fill,sizeof(fill)))>0) filled+=(size_t)n;
    assert(errno==EAGAIN);
    assert(fcntl(sink[1],F_SETFL,fcntl(sink[1],F_GETFL)&~O_NONBLOCK)==0);
    init_case(argv[1]);
#ifdef PERSIST_QUEUE_CAP
    assert(persist_worker_start());
#endif
    pthread_t producer; assert(pthread_create(&producer,NULL,dispatcher,NULL)==0);
    char c; assert(read(ready[0],&c,1)==1); uint64_t began=persist_now_ms();
    bool passed=command("COUNT","COUNT|0|0|0\n",180);
    if (!passed) fprintf(stderr,"FAIL COUNT blocked behind real persist write while gate held\n");
    pthread_t stopper; bool have_stopper=false;
    if (passed) {
        uint64_t dropped=g_persist_io.dropped;
        passed=command("LOAD","LOADED\n",180) && g_persist_io.dropped>dropped;
        passed=command("CLEAR_IO","OK\n",180) && passed;
        passed=command("CLEAR_IO","OK\n",180) && passed;
        passed=command("POST","POSTED\n",180) && passed;
        assert(write(clients[1],"QUIT",5)==5); assert(pthread_join(producer,NULL)==0);
        assert(pthread_create(&stopper,NULL,stop_owner,NULL)==0); have_stopper=true;
        struct pollfd nofd={.fd=-1}; assert(poll(&nofd,0,20)==0);
        passed=!atomic_load(&stop_done) && passed; /* owner join may wait for active IO, outside metadata locks */
        persist_lazy_tick(); /* metadata remains usable while stop waits for the active write */
    }
    /* Close the original writer; drain until the worker closes its duplicate. */
    close(sink[1]); sink[1]=-1;
    assert(fcntl(sink[0],F_SETFL,fcntl(sink[0],F_GETFL)&~O_NONBLOCK)==0);
    size_t drained=0; while ((n=read(sink[0],fill,sizeof(fill)))>0) drained+=(size_t)n; assert(n==0);
    if (!have_stopper) { assert(write(clients[1],"QUIT",5)==5); assert(pthread_join(producer,NULL)==0); }
    else assert(pthread_join(stopper,NULL)==0);
#ifdef PERSIST_QUEUE_CAP
    if (!have_stopper) persist_worker_stop();
    if (have_stopper) {
        FILE* f=fopen(g_persist_io.path,"r"); assert(f); char content[8192]={0}; size_t len=fread(content,1,sizeof(content)-1,f); fclose(f);
        passed=len>0 && strstr(content,"POST_CLEAR") && !strstr(content,"PRE_CLEAR_") && passed;
        read_file(g_persist_sys.path,content,sizeof(content));
        passed=strstr(content,"|WARN|KEEP_SYS_GATED\n") && passed;
    }
#else
    free(g_persist_io.stage); free(g_persist_sys.stage);
#endif
    passed=!atomic_load(&main_disk_io) && passed;
    destroy_buf(&g_io_buf); destroy_buf(&g_sys_buf); destroy_buf(&g_logcat_buf);
    close(sink[0]); for(int i=0;i<2;i++){close(ready[i]);close(clients[i]);}
    int after=fd_count(); assert(before==after); alarm(0);
    printf("%s persist isolation: elapsed=%llu ms drop=%llu fd_before=%d fd_after=%d children=0 threads_joined=%d filled=%zu drained=%zu\n",
        passed?"PASS":"FAIL",(unsigned long long)(persist_now_ms()-began),(unsigned long long)g_persist_io.dropped,before,after,have_stopper?3:1,filled,drained);
    return passed?0:1;
}
