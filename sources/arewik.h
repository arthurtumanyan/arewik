/*
Copyright [2013] [Arthur Tumanyan <arthurtumanyan@gmail.com]
Copyright [2013] [Netangels,LLC www.netangels.net]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef AREWIK_H
#define	AREWIK_H

#ifdef	__cplusplus
extern "C" {
#endif
#define FREE(ptr) do{ \
    free((ptr));      \
    (ptr) = NULL;     \
  }while(0)
    
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <error.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>     /*  socket definitions        */
#include <sys/types.h>        /*  socket types              */
#include <arpa/inet.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <sys/file.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <pthread.h>
#include <zlib.h>
#include <regex.h>
#include <netdb.h>
#include <ftw.h>
#include <curl/curl.h>
#include <libconfig.h>
#include "errmsg.h" 


#define KB 1024UL
#define MB 1024UL * KB
#define GB 1024UL * MB
#define TB 1024UL * GB

#define no_argument            0
#define required_argument      1
#define optional_argument      2

#define DEFAULT_LISTEN_IP       "127.0.0.1"
#define DEFAULT_LISTEN_PORT     1114

#define DEFAULT_WEBHDFS_BUFF_SIZE 128 * KB
#define WATCHDOG_T 10
#define MAXLINE 1024
#define NET_MAX_BUFF 512
#define MODULES_COUNT   4
#define CFG_PARAM_LEN 64  
#define ROUTES_MAX_COUNT 64    
#define MODULES_MAX_COUNT MODULES_COUNT
#define COMPRESSORS_CNT 2  
#define NOSQL_CNT 5
#define ROTATE_METHOD_CNT 3
#define MAX_CON_PER_ROUTER 1024 /* this number must be more or equal to maxcon param in config file */
#define POSSIBLE_FHNDL  ROUTES_MAX_COUNT * MAX_CON_PER_ROUTER
#define SOURCE_IPNETCNT_PER_ROUTE 64

#if (LIBCONFIG_VER_MAJOR == 1 && LIBCONFIG_VER_MINOR >= 4) 
    typedef int ARW_INT;
#else
    typedef long ARW_INT;
#endif
    //
    const char ident[] = "AreWikLogAggregator";
    const char welcome[] = "AreWik-0.1-unstable\n";

    char TMP_MSG[MAXLINE];

    struct passwd *pwd;
    struct group *grp;
    struct stat status;
    uid_t my_uid;
    gid_t my_gid;
    pid_t pid, sid;
    off_t file_size;

    pthread_t listen_thread;
    pthread_t rotate_thread;
    pthread_t sheduler_thread;
    pthread_t watch_thread;
    pthread_t pbuffer_thread;
    pthread_t p_child;

    int wtresult, childres, bfres, shedres, rotres, listenres;
    int wtid = 1, childtid = 2, shedtid = 3, bftid = 4, rotatetid = 5, listentid = 6;

    pthread_mutex_t t_mutex, t_mutex2, t_mutex_child, t_webhdfs, t_error, t_process_w;
    pthread_mutex_t buffer_mutex;

    bool rotate_stop_flag;
    bool watchdog_stop_flag;
    bool sheduler_stop_flag;
    bool pbuffer_stop_flag;
    bool listen_stop_flag;

    DIR *buf_dir;
    struct dirent *entry;
    struct stat statbuf;

    typedef enum {
        SNAPPY, GZIP, NONE
    } COMPRESSOR;

    enum _TRANSFER_ACTIONS {
        UNINITIALIZED, STOP, PAUSE, START
    } **TRANSFER_ACTIONS;

    typedef enum {
        RIAK, ESEARCH, WEBHDFS, BUFFER, S_NONE
    } NOSQL;

    typedef enum {
        BYSIZE, BYTIME, RNONE
    } ROTATE_METHOD;


    const char *compressors_table[COMPRESSORS_CNT] = {"snappy", "gzip"};
    const char *nosql_table[NOSQL_CNT] = {

        "riak", "esearch", "webhdfs", "buffer", ""
    };
    const char *rotatem_table[ROTATE_METHOD_CNT] = {"by_size", "by_time", ""};

    struct _CPRESS_FUNCT {
        COMPRESSOR type;
        char * (* compress_function) (char *, int);
    } CPRESS_FUNCT[COMPRESSORS_CNT];

    typedef struct {
        int id;
        bool enabled;
        const char *name;
        int (* process_function) (char *, char *, int, int);
        void (* init_function) (int, int);
        void (* close_function) (int, int);
    } MODULE;

    typedef struct {
        char *dst_user; //[16];
        char *dst_path; //[NAME_MAX];
        char *active_namenode; //[NAME_MAX];
    } WEBHDFS_TO;

    typedef struct {
        char proto[6];
        char dst_ip[16];
        int dst_port;
        char index[64];
        char type[64];
    } ESEARCH_TO;

    typedef struct {
        char bucket[64];
        char key[64];
        char proto[6];
        char ip[16];
        int port;
    } RIAK_TO;

    typedef struct _ROUTES {
        int id;
        int enabled;
        int use_compression;
        int compression_ratio;
        int rotate;
        ROTATE_METHOD rotate_method;
        int rotate_period;
        off_t rotate_file_limit;
        int buffering;
        bool is_active;
        COMPRESSOR compressor;

        struct {
            char address[16];
            char netmask[16];
            int lastoctet_range;
        } from[SOURCE_IPNETCNT_PER_ROUTE];

        int send_data_by_block;
        off_t send_data_size;
        int buffersize;
        int readline;
        char to[CFG_PARAM_LEN];
        char router[CFG_PARAM_LEN];
        char dst_path_prefix[CFG_PARAM_LEN];
        char dst_path[CFG_PARAM_LEN];
        char dst_auth_user[NAME_MAX];
        char dst_auth_pwd[NAME_MAX];

        char namenode1[NAME_MAX];
        char namenode2[NAME_MAX];
        /* esearch */
        char index_name[64];
        char type_name[64];
        char uniqueid[64];
        /* riak */
        char bucket[64];
        char key[64];
        int auto_key;
    } ROUTES;

    typedef struct {
        int router_id;
        int con_counter;
        COMPRESSOR compressor;
        time_t timestamp;
        char bf_name[PATH_MAX];
    } BUF_THREAD_PARAMS;

    typedef struct {
        char ip[16];
        int listenfd;
        int connfd;
        int port;
        int counter;
        int con_counter;
        int epoll;
        struct epoll_event event;
        struct epoll_event * events;
    } PROC_THREAD_PARAMS;

    typedef struct {
        int maxcon;
        int routes_cnt;
        int proxymode;
        int autoreconfigure;
        int reconfigure_interval;
        int watchdog_interval;
        int ping_interval;
        int use_syslog;
        int use_resolver;
        int socktimeout;
        int epolltimeout;
        int useworker;
        int workers;
        char identline[64];
        char * custom_logfile_name;
        char * debug_logfile_name;
        char * connections_logfile_name;
        char * access_logfile_name;
        char active_namenode[NAME_MAX];
        ROUTES routes[ROUTES_MAX_COUNT];
        MODULE modules[MODULES_MAX_COUNT];

    } GLOBALS;

    typedef struct {
        unsigned ce; // connection error
        unsigned fe; // file error
        unsigned ie; // internal error
    } STATS;

    struct {
        char *storagedir;
        char *bufferdir;
        char *pidfile;
        char *logdir;
        char *configfile;
        char *user;
        char *group;
        char *wdir;
        char *listen_host;
        int listen_port;
        int verbosity;
        int debuginfo;
        int foreground;

    } arguments;

    static const struct option longOpts[] = {
        { "pidfile", required_argument, NULL, 'p'},
        { "logdir", required_argument, NULL, 'l'},
        { "configfile", required_argument, NULL, 'c'},
        { "user", required_argument, NULL, 'u'},
        { "group", required_argument, NULL, 'g'},
        { "listen-host", required_argument, NULL, 'H'},
        { "listen-port", required_argument, NULL, 'P'},
        { "working-dir", required_argument, NULL, 'D'},
        { "verbose", no_argument, NULL, 'v'},
        { "foreground", no_argument, NULL, 'f'},
        { "help", no_argument, NULL, 'h'},
        { "debug-mode", no_argument, NULL, 'd'},
        { "storage-dir", required_argument, NULL, 's'},
        { "buffer-dir", required_argument, NULL, 'B'},
        { NULL, no_argument, NULL, 0}
    };

    struct _handles {
        COMPRESSOR type;
        NOSQL nosql_type;
        FILE * file_fd;
        gzFile zfile_fd;
        FILE * buffer_fd;
    } **handles; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];

    struct _fstruct {
        char * filename;
        time_t timestamp;
    } **files; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];

    struct _active_connections {
        char ip[16];
        int port; /* for further needs */
        int connfd;
        int conno;
    } **active_connections; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];

    struct _in_process_buff {
        char buffer[PATH_MAX];
        BUF_THREAD_PARAMS btp;
    } *in_process_buff; //[POSSIBLE_FHNDL];

    FILE * access_fd = NULL;
    FILE * custom_fd = NULL;
    FILE * debug_fd = NULL;
    FILE * conlog_fd = NULL;
    FILE * pid_fd = NULL;

    FILE * **buffer_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
    FILE * **snappy_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
    FILE * **plain_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
    gzFile gzip_fd[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];

    time_t ticks;
    time_t start_time;
    struct tm * timeinfo;

    typedef struct {
        CURL * fd;
        char remoteFile[PATH_MAX];
        char url[PATH_MAX];
        char backupUrl[PATH_MAX];
        char pureUrl[PATH_MAX];
        WEBHDFS_TO _MY_TO;
    } _webhdfs_fd;

    typedef struct {
        CURL * cp;
        char url[PATH_MAX];
    } _esearch_fd;

    typedef struct {
        CURL * cp;
        char url[PATH_MAX];
    } _riak_fd;

    _webhdfs_fd **webhdfs_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
    _esearch_fd **esearch_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
    _riak_fd **riak_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];

    GLOBALS globals, *glob;
    STATS **stats; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];

#ifdef	__cplusplus
}
#endif

#endif
