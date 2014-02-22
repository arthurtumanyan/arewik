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

#ifndef PROTOS_H
#define	PROTOS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "mod_webhdfs.h"
    /*
     GLOBAL
     */
    extern void * xmalloc(size_t size);
    extern void * xrealloc(void *ptr, size_t size);
    extern void * xcalloc(size_t nmemb, size_t size);
    extern void print_usage();
    extern void halt();
    extern void trim(const char *);
    extern bool FileExists(char *);
    extern bool DirectoryExists(const char *);
    extern void set_sig_handler();
    extern void savePid();
    extern int checkPid();
    extern void removePid();
    extern bool hasRightOwner(const char *);
    extern void setRightOwner(const char *);
    extern int setPerm(const char *fpath, const struct stat *sb, int tflag);
    //extern int process_input_data(char *, int, int);
    extern off_t get_file_size(const char *);
    extern off_t get_file_size_by_hnd(FILE * hnd);
    extern void enableModule(char *);
    extern bool module_exists(char *module);
    extern int call_module(char *, char *, char *, int, int);
    extern void init_descriptors();
    extern void rotate_logs(); // not yet implemented
    extern int find_proper_router(char *);
    extern int find_proper_router_counter(char *);
    extern char * get_router_name(int);
    extern char * get_router_from(int);
    extern char * get_router_to(int);
    extern int get_routerc_by_dst(char *);
    extern int get_router_counter(int);
    extern int get_routerc_by_nn(char *);
    extern bool is_route_absent(char *);
    extern int has_applicable_route(char *);
    extern int is_route_disabled(int);
    extern int get_rand();
    extern void close_descriptor(int, int);
    extern bool init_descriptor(int, int);
    extern void init_arrays();
    extern void * watchdog(void *);
    extern void * sheduler(void *);
    extern bool is_int(double);
    extern void low_string(char *);
    extern char * str_replace(const char *, const char *, const char *);
    extern bool mkPath(char *);
    extern bool prepareLocalPath(char *);
    extern bool isLikeUrl(char *);
    extern struct passwd * systemUserExists(char *);
    extern void * create_child_processor_poll(void * ptr); // deprecated
    extern void * spawn_child_processor(void * ptr);
    extern void do_read_data(int fd, int rc, int epollfd, char *ip, int port);
    //
    /*
     Logging
     */
    extern FILE * openCustomLog();
    extern void writeToCustomLog(char *);
    extern void closeCustomLog();

    extern FILE * openDebugLog();
    extern void writeToDebugLog(char *);
    extern void closeDebugLog();

    extern FILE * openAccessLog();
    extern void writeToAccessLog(char *ip, char *ident, char *authuser, char *request, char * response, long bytes, char *backend);
    extern void closeAccessLog();

    extern FILE * openConLog();
    extern void writeToConLog();
    extern void closeConLog();

    extern void VERBOSE(char *);
    extern void write_syslog(char *);
    /*
     Network
     */

    extern ssize_t Readline(int, void *, size_t);
    extern ssize_t Writeline(int, const void *, size_t);
    extern void do_listen();
    extern void spawn_threads();
    extern void create_poll_listener(); // deprecated
    extern int setnonblocking(int);
    extern ssize_t Writeline(int, const void *, size_t);
    extern bool host_is_alive(char *, int);
    extern int findConnectionIdByIp(char *);
    extern void killClient(int, int);
    extern bool contain_active_connections(int);
    extern void start_listening();
    extern void * init_unsecure_server(void *); /* without SSL support */
    extern char * nslookup(char *);
    extern int isValidIP(char *);
    extern bool isValidPort(const char *);
    extern void init_active_c_table();
    extern void save_active_connection(char *, int, int, int);
    extern void deactivate_connection(int, int);
    extern void scan_connections();
    extern bool is_processing(char *);
    extern bool isTime(unsigned int);
    extern char *strip_chars(char *, char *);
    extern void set_thread_signalmask(sigset_t);
    extern bool is_disabled_module(char *);
    extern bool ensure_module_is_enabled(char *);
    extern bool init_nosql_connections(int, int, int, bool);

    /*
     Config
     */

    extern GLOBALS * readConfig(char *);
    extern void reconfigure();
    extern char * parsePathPrefix(const char *, int, int);
    extern bool isIpRange(const char *);
    extern bool isSubnet(const char *);
    extern bool isValidHostname(const char *);
    extern bool IsIPInRange(char *, char *, char *);
    /*
     Compressor
     */
    extern int get_compressor(const char *);
    extern int compression_ratio(int);

    extern char * compress_snappy(char *, int);
    extern char * compress_lzo(char *, int);
    extern char * compress_bz2(char *, int);
    extern char * compress_gzip(char *, int);

    extern FILE * open_snappy_file(char *, int, int);
    extern void write_snappy(FILE *, char *);
    extern void close_snappy_files();
    extern void close_snappy_file(int, int);

    extern FILE * open_plain_file(char *, int, int);
    extern void write_plain(FILE *, char *);
    extern void close_plain_files();
    extern void close_plain_file(int, int);

    extern gzFile open_gzip_file(char *, int, int);
    extern void write_gzip(gzFile, voidpc);
    extern void close_gzip_files();
    extern void close_gzip_file(int, int);
    //

    /*
     WEBHDFS
     */
    extern void init_webhdfs_arrays();
    extern _webhdfs_fd init_webhdfs_module(int, int);
    extern int process_webhdfs(char *, char *, int, int);
    extern WEBHDFS_TO parseWEBHDFSTo(int);
    extern bool ping_webhdfs(char *, int);
    extern void close_webhdfs(int, int);
    extern void close_webhdfs_handles();
    extern bool webhdfs_mkdir(char *, int);
    extern bool HadoopPathExists(char *);
    extern bool prepareRemotePath(char *, int);
    extern char * get_active_namenode(int);
    extern void do_webhdfs_rotate(int, int);
    extern bool webhdfs_setowner(char *, char *, char *);
    /*
     RIAK
     */
    extern _riak_fd init_riak_module(int, int);
    extern int process_riak(char *, char *, int, int);
    extern bool ping_riak(char *, int, char *);
    extern RIAK_TO parseRIAKTo(char *);
    extern void close_riak(int, int);
    extern void close_riak_handles();
    /*
     ESEARCH
     */
    extern _esearch_fd init_esearch_module(int, int);
    extern int process_esearch(char *, char *, int, int);
    extern bool ping_esearch(char *, int);
    extern ESEARCH_TO parseESEARCHTo(char *);
    extern void close_esearch(int, int);
    extern void close_esearch_handles();
    /*
     PLAIN
     */
    extern int process_plain(char *, char *, int, int);

    /*
     Debug
     */
    extern void dump_routes(int, char *, bool);
    extern void dump_active_connections();

    /*
     Buffers
     */
    extern int write_to_buffer(int, int, char *);
    extern FILE * open_buffer(int, int);
    extern void close_buffer(int, int);
    extern void close_buffer_files();

    extern bool dump_buffer(int, int, int, char *, int, time_t);
    extern void delete_buffer(char *);
    extern FILE * open_buffer_file(char *);
    extern bool upload_buffer_file(FILE *, int, int, time_t);
    extern int scan_buffer_dir(const char *, const struct stat *, int);

    /*
     Rotate
     */
    extern bool is_rotate_time(int, char *);
    extern bool is_wrotate_time(int, off_t);
    extern void scan_for_rotate(int, int);
    extern void * rotate(void *);
    extern void do_rotate(int, int);


#ifdef	__cplusplus
}
#endif

#endif	/* PROTOS_H */

