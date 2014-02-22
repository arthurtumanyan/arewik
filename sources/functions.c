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
#include "arewik.h"
#include "protos.h"

void spawn_threads() {

    pthread_mutex_lock(&t_error);
    writeToCustomLog("Spawning threads");
    pthread_mutex_unlock(&t_error);

    wtresult = pthread_create(&watch_thread, NULL, watchdog, &wtid);
    if (wtresult == 0) {
        pthread_mutex_lock(&t_error);
        writeToCustomLog("Watchdog started in a separate thread");
        pthread_mutex_unlock(&t_error);
    } else {
        pthread_mutex_lock(&t_error);
        writeToCustomLog("Unable to start watchdog. Exiting");
        halt();
        pthread_mutex_unlock(&t_error);
    }
    sleep(1);
    ////////////////////////////////////////////////////////////////////////////////
    shedres = pthread_create(&sheduler_thread, NULL, sheduler, &shedtid);
    if (shedres == 0) {
        pthread_mutex_lock(&t_error);
        writeToCustomLog("Sheduler started in a separate thread");
        pthread_mutex_unlock(&t_error);
    } else {
        pthread_mutex_lock(&t_error);
        writeToCustomLog("Unable to start sheduler. Exiting");
        halt();
        pthread_mutex_unlock(&t_error);
    }
    sleep(1);
    ////////////////////////////////////////////////////////////////////////////////
    rotres = pthread_create(&rotate_thread, NULL, rotate, &rotatetid);
    if (rotres == 0) {
        pthread_mutex_lock(&t_error);
        writeToCustomLog("Rotator started in a separate thread");
        pthread_mutex_unlock(&t_error);
    } else {
        pthread_mutex_lock(&t_error);
        writeToCustomLog("Unable to start rotator. Exiting");
        halt();
        pthread_mutex_unlock(&t_error);
    }
}

off_t get_file_size(const char * file_name) {
    struct stat sb;
    if (stat(file_name, & sb) != 0) {
        return -1;
    } else {
        return sb.st_size;
    }
}

off_t get_file_size_by_hnd(FILE * hnd) {
    fseek(hnd, 0L, SEEK_END);
    return (NULL != hnd) ? ftell(hnd) : -1;
}

/**
 *
 * @param str
 * @return
 */
int isValidIP(char *str) {

    int segs = 0; /* Segment count. */
    int chcnt = 0; /* Character count within segment. */
    int accum = 0; /* Accumulator for segment. */

    /* Catch NULL pointer. */

    if (str == NULL)
        return 0;

    /* Process every character in string. */

    while (*str != '\0') {
        /* Segment changeover. */

        if (*str == '.') {
            /* Must have some digits in segment. */

            if (chcnt == 0)
                return 0;

            /* Limit number of segments. */

            if (++segs == 4)
                return 0;

            /* Reset segment values and restart loop. */

            chcnt = accum = 0;
            str++;
            continue;
        }

        /* Check numeric. */

        if ((*str < '0') || (*str > '9'))
            return 0;

        /* Accumulate and check segment. */

        if ((accum = accum * 10 + *str - '0') > 255)
            return 0;

        /* Advance other segment specific stuff and continue loop. */

        chcnt++;
        str++;
    }

    /* Check enough segments and enough characters in last segment. */

    if (segs != 3)
        return 0;

    if (chcnt == 0)
        return 0;

    /* Address okay. */

    return 1;
}

/**
 *
 * @param p
 * @return
 */
bool isValidPort(const char * p) {
    int port = 0, z = 0;
    if (p == NULL) {
        return false;
    }
    if (0 != (z = sscanf(p, "%d", &port))) {
        if (port > 0 && port <= 65535) {
            return true;
        }
    }
    return false;
}

/**
 *
 * @param path
 * @return
 */
bool FileExists(char *path) {
    FILE *fp = fopen(path, "r");
    if (fp) {
        fclose(fp);
        return true;
    } else {
        return false;
    }
}

/**
 *
 * @param pzPath
 * @return
 */
bool DirectoryExists(const char* pzPath) {
    if (pzPath == NULL) return false;

    DIR *pDir;
    bool bExists = false;

    pDir = opendir(pzPath);

    if (pDir != NULL) {
        bExists = true;
        (void) closedir(pDir);
    }

    return bExists;
}

/**
 *
 */
void savePid() {
    int fsz = sizeof (arguments.pidfile);
    int sz = fsz + 50;
    char func_msg[sz];

    if ((pid_fd = fopen(arguments.pidfile, "w")) == NULL) {
        snprintf(func_msg, sz, "Cannot create PID file '%s'.Exiting nicely! - %s", arguments.pidfile, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
        exit(EXIT_FAILURE);
    } else {
        setRightOwner(arguments.pidfile);
        snprintf(func_msg, sz, "Process ID stored in: '%s',%d", arguments.pidfile, errno);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
    }
    fprintf(pid_fd, "%d", getpid());

    if (pid_fd)fclose(pid_fd);

    if (0 != chown(arguments.pidfile, my_uid, my_gid)) {
        snprintf(func_msg, sz, "Cannot chown file '%s',%s", arguments.pidfile, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
    }
}

/**
 *
 * @return
 */
int checkPid() {
    pid_t S_PID;
    if ((pid_fd = fopen(arguments.pidfile, "r")) != NULL) {
        (void) fscanf(pid_fd, "%d", &S_PID);
        if (pid_fd)fclose(pid_fd);

        if (kill(S_PID, 18) == 0) {
            printf("Can be only one running daemon with the same settings!Quitting...\n");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

/**
 *
 */
void removePid() {
    int fsz = sizeof (arguments.pidfile);
    int sz = fsz + 64;
    char func_msg[sz];
    if (0 != unlink(arguments.pidfile)) {
        snprintf(func_msg, sz, "Cannot unlink file '%s',%s", arguments.pidfile, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);

    } else {
        snprintf(func_msg, sz, "Pid file '%s' removed", arguments.pidfile);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
    }
}

/**
 *
 * @param str
 */
void low_string(char *str) {
    int h;
    for (h = 0; h < strlen(str); h++)str[h] = tolower((int) str[h]);
}

/**
 *
 * @param str
 */
void trim(const char *str) {
    char *p;

    if ((p = strchr(str, '\r')) != NULL) {
        *p = '\0';
    }
    if ((p = strchr(str, '\n')) != NULL) {
        *p = '\0';
    }
}

/**
 *
 */
void init_arrays() {

    TRANSFER_ACTIONS = xmalloc(globals.routes_cnt * sizeof (enum _TRANSFER_ACTIONS *));
    int f = 0;
    for (f = 0; f < globals.routes_cnt; f++) {
        TRANSFER_ACTIONS[f] = xmalloc(globals.maxcon * sizeof (enum _TRANSFER_ACTIONS));
    }
    //
    f = 0;
    handles = xmalloc(globals.routes_cnt * sizeof (struct _handles *));
    for (f = 0; f < globals.routes_cnt; f++) {
        handles[f] = xmalloc(globals.maxcon * sizeof (struct _handles));
        handles[f]->buffer_fd = NULL;
        handles[f]->file_fd = NULL;
        handles[f]->nosql_type = S_NONE;
        handles[f]->type = NONE;
        handles[f]->zfile_fd = Z_NULL;
    }
    //
    f = 0;
    files = xmalloc(globals.routes_cnt * sizeof (struct _fstruct *));
    for (f = 0; f < globals.routes_cnt; f++) {
        files[f] = xmalloc(globals.maxcon * sizeof (struct _fstruct));
        files[f]->filename = NULL;
        files[f]->timestamp = time(0);
    }
    //
    f = 0;
    active_connections = xmalloc(globals.routes_cnt * sizeof (struct _active_connections *));
    for (f = 0; f < globals.routes_cnt; f++) {
        active_connections[f] = xmalloc(globals.maxcon * sizeof (struct _active_connections));
    }
    //
    in_process_buff = xmalloc((globals.routes_cnt * globals.maxcon) * sizeof (struct _in_process_buff));
    //
    f = 0;
    stats = xmalloc(globals.routes_cnt * sizeof (STATS *));
    for (f = 0; f < globals.routes_cnt; f++) {
        stats[f] = xmalloc(globals.maxcon * sizeof (STATS));
    }
    //
    f = 0;
    webhdfs_fd = xmalloc(globals.routes_cnt * sizeof (_webhdfs_fd *));
    for (f = 0; f < globals.routes_cnt; f++) {
        webhdfs_fd[f] = xmalloc(globals.maxcon * sizeof (_webhdfs_fd));
    }
    //
    f = 0;
    esearch_fd = xmalloc(globals.routes_cnt * sizeof (_esearch_fd *));
    for (f = 0; f < globals.routes_cnt; f++) {
        esearch_fd[f] = xmalloc(globals.maxcon * sizeof (_esearch_fd));
    }
    //
    f = 0;
    riak_fd = xmalloc(globals.routes_cnt * sizeof (_riak_fd *));
    for (f = 0; f < globals.routes_cnt; f++) {
        riak_fd[f] = xmalloc(globals.maxcon * sizeof (_riak_fd));
    }
    //
    f = 0;
    buffer_fd = xmalloc(globals.routes_cnt * sizeof (FILE **));
    for (f = 0; f < globals.routes_cnt; f++) {
        buffer_fd[f] = xmalloc(globals.maxcon * sizeof (FILE **));
    }
    //
    f = 0;
    snappy_fd = xmalloc(globals.routes_cnt * sizeof (FILE **));
    for (f = 0; f < globals.routes_cnt; f++) {
        snappy_fd[f] = xmalloc(globals.maxcon * sizeof (FILE **));
    }
    //
    f = 0;
    plain_fd = xmalloc(globals.routes_cnt * sizeof (FILE **));
    for (f = 0; f < globals.routes_cnt; f++) {
        plain_fd[f] = xmalloc(globals.maxcon * sizeof (FILE **));
    }
    //
    ////////////////////////////////////////////////////////////////////////////
    //
    int i = 0, j = 0;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            TRANSFER_ACTIONS[i][j] = UNINITIALIZED;
        }
    }

}

/**
 *
 */
void halt() {

    int sz = 15;
    char func_msg[sz];

    pthread_mutex_lock(&t_error);
    writeToCustomLog("Closing open handles");
    pthread_mutex_unlock(&t_error);

    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            close_descriptor(i, j);
        }
    }
    pthread_mutex_lock(&t_error);
    writeToCustomLog("Terminating threads");
    pthread_mutex_unlock(&t_error);
    watchdog_stop_flag = true;
    sheduler_stop_flag = true;
    pbuffer_stop_flag = true;
    listen_stop_flag = true;
    sleep(3);
    removePid();
    curl_global_cleanup();
    //

    snprintf(func_msg, sz, "%s", "Shutting down");
    pthread_mutex_lock(&t_error);
    writeToCustomLog(func_msg);
    pthread_mutex_unlock(&t_error);
    closeCustomLog();
    closeDebugLog();
    closeConLog();
    closeAccessLog();

    if (arguments.pidfile) {
        FREE(arguments.pidfile);
        arguments.pidfile = NULL;
    }

    if (arguments.logdir) {
        FREE(arguments.logdir);
        arguments.logdir = NULL;
    }

    if (arguments.storagedir) {
        FREE(arguments.storagedir);
        arguments.storagedir = NULL;
    }

    if (arguments.bufferdir) {
        FREE(arguments.bufferdir);
        arguments.bufferdir = NULL;
    }

    if (arguments.configfile) {
        FREE(arguments.configfile);
        arguments.configfile = NULL;
    }

    if (arguments.user) {
        FREE(arguments.user);
        arguments.user = NULL;
    }

    if (arguments.group) {
        FREE(arguments.group);
        arguments.group = NULL;
    }

    if (arguments.wdir) {
        FREE(arguments.wdir);
        arguments.wdir = NULL;
    }

    if (arguments.listen_host) {
        FREE(arguments.listen_host);
        arguments.listen_host = NULL;
    }

    if (globals.custom_logfile_name) {
        FREE(globals.custom_logfile_name);
        globals.custom_logfile_name = NULL;
    }

    if (globals.debug_logfile_name) {
        FREE(globals.debug_logfile_name);
        globals.debug_logfile_name = NULL;
    }

    if (globals.connections_logfile_name) {
        FREE(globals.connections_logfile_name);
        globals.connections_logfile_name = NULL;
    }

    if (globals.access_logfile_name) {
        FREE(globals.access_logfile_name);
        globals.access_logfile_name = NULL;
    }

    exit(EXIT_SUCCESS);
}

/**
 *
 */
void print_usage() {

    printf("%s\t%30s", "-p |--pidfile", "pidfile\n");
    printf("%s\t%30s", "-l |--logfile", "logfile\n");
    printf("%s\t%33s", "-c |--configfile", "configuration file\n");
    printf("%s\t%35s", "-u |--user", "working user\n");
    printf("%s\t%36s", "-g |--group", "working group\n");
    printf("%s\t%32s", "-H |--listen-host", "listen IP address\n");
    printf("%s\t%26s", "-P |--listen-port", "listen port\n");
    printf("%s\t%32s", "-D |--working-dir", "working directory\n");
    printf("%s\t%32s", "-s |--storage-dir", "storage directory\n");
    printf("%s\t%39s", "-v |--verbose", "enable verbosity\n");
    printf("%s\t%32s", "-f |--foreground", "run in foreground\n");
    printf("%s\t%32s", "-h |--help", "this help\n");
    printf("%s\t%36s", "-d |--debug-mode", "very detailed logging\n");
    printf("%s\t%31s", "-B |--buffer-dir", "buffer directory\n");
    exit(EXIT_SUCCESS);

}

/**
 *
 * @param c
 * @return
 */
int compression_ratio(int c) {
    if (globals.routes[c].compression_ratio < 0 || globals.routes[c].compression_ratio > 9) {
        globals.routes[c].compression_ratio = 5;
    }
    return globals.routes[c].compression_ratio;
}

/**
 * man 3 rand
 * @return
 */
int get_rand() {
    static unsigned long next = 1;
    next = next * 1103515245 + 12345;
    return ((unsigned) (next / 65536) % 32768);

}

/**
 *
 * @param path
 */
void setRightOwner(const char *path) {
    if (NULL == path)return;
    if (hasRightOwner(path))return;
    int sz = strlen(path) + 80;
    char func_msg[sz];
    int rc;
    struct passwd *pw = getpwnam(arguments.user);
    struct group *gr = getgrnam(arguments.group);
    if (NULL == pw || NULL == gr) {
        snprintf(func_msg, sz, "No such user/group: %s/%s", arguments.user, arguments.group);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
        exit(EXIT_FAILURE);
    }
    rc = chown(path, pw->pw_uid, gr->gr_gid);
    if (rc == -1) {
        snprintf(func_msg, sz, "Cannot chown file/directory '%s',%s", path, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
    }
}

/**
 *
 * @param path
 * @return
 */
bool hasRightOwner(const char *path) {
    if (NULL == path)return false;
    stat(path, &status);
    struct passwd *pw = getpwuid(status.st_uid);
    struct group *gr = getgrgid(status.st_gid);
    int i = 0;
    if ((pw != 0) && (0 == strcmp(pw->pw_name, arguments.user))) {
        i++;
    }
    if ((gr != 0) && (0 == strcmp(gr->gr_name, arguments.group))) {
        i++;
    }
    if (i < 2) {
        return false;
    } else {
        return true;
    }
}

/**
 *
 */
void init_descriptors() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            snappy_fd[i][j] = NULL;
            gzip_fd[i][j] = Z_NULL;
            plain_fd[i][j] = NULL;
            buffer_fd[i][j] = NULL;
            files[i][j].filename = NULL;
            files[i][j].timestamp = 0;
        }
    }
}

/**
 *
 * @param from
 * @param j
 */
bool init_descriptor(int rc, int con_counter) {
    int sz = 50;
    char func_msg[sz];
    //
    if (0 == strcmp(globals.routes[rc].router, "plain")) {

        if (globals.routes[rc].use_compression) {
            switch (globals.routes[rc].compressor) {
                case SNAPPY:
                    snappy_fd[rc][con_counter] = open_snappy_file(globals.routes[rc].to, rc, con_counter);
                    if (NULL == snappy_fd[rc][con_counter]) {
                        snprintf(func_msg, sz, "%s", "init_descriptors(): snappy error");
                        pthread_mutex_lock(&t_error);
                        writeToDebugLog(func_msg);
                        pthread_mutex_unlock(&t_error);
                        return false;
                    }
                    handles[rc][con_counter].type = SNAPPY;
                    handles[rc][con_counter].nosql_type = S_NONE;
                    TRANSFER_ACTIONS[rc][con_counter] = START;
                    break;
                case GZIP:
                    gzip_fd[rc][con_counter] = open_gzip_file(globals.routes[rc].to, rc, con_counter);
                    if (Z_NULL == gzip_fd[rc][con_counter]) {
                        snprintf(func_msg, sz, "%s", "init_descriptors(): gzip error");
                        pthread_mutex_lock(&t_error);
                        writeToDebugLog(func_msg);
                        pthread_mutex_unlock(&t_error);
                        return false;
                    }
                    handles[rc][con_counter].type = GZIP;
                    handles[rc][con_counter].nosql_type = S_NONE;
                    TRANSFER_ACTIONS[rc][con_counter] = START;
                    break;
                default:
                    break;
            } /* use compression */
        } else {

            plain_fd[rc][con_counter] = open_plain_file(globals.routes[rc].to, rc, con_counter);
            if (NULL == plain_fd[rc][con_counter]) {
                snprintf(func_msg, sz, "%s", "init_descriptors(): plain error");
                pthread_mutex_lock(&t_error);
                writeToDebugLog(func_msg);
                pthread_mutex_unlock(&t_error);
                return false;
            }
            handles[rc][con_counter].type = NONE;
            handles[rc][con_counter].nosql_type = S_NONE;
            TRANSFER_ACTIONS[rc][con_counter] = START;

        } /* do not use compression */

    } else {
        // do not open any connection to remote servers while the remote server marked as dead

        if (!globals.routes[rc].is_active) {
            if (globals.routes[rc].buffering) {
                buffer_fd[rc][con_counter] = open_buffer(rc, con_counter);
                handles[rc][con_counter].nosql_type = BUFFER;
                TRANSFER_ACTIONS[rc][con_counter] = START;

            }
        } else {
            return init_nosql_connections(globals.routes[rc].id, rc, con_counter, false); /* router_id, router counter, connection counter */

        } /* NOSQL */
    }
    return true;
}

/**
 *
 * @param router_id
 * @param counter
 * @param con_counter
 * @param buffer
 */
bool init_nosql_connections(int router_id, int counter, int con_counter, bool buffer) {

    if (0 == strcmp(globals.routes[counter].router, "riak")) {
        if (!ensure_module_is_enabled("riak")) {
            return false;
        }
        riak_fd[counter][con_counter] = init_riak_module(counter, con_counter);
        if (NULL == riak_fd[counter][con_counter].cp) {
            Writeline(active_connections[counter][con_counter].connfd, NOT_APPLICABLE_ROUTE, strlen(NOT_APPLICABLE_ROUTE));
            killClient(counter, con_counter);
            return false;
        }
        handles[counter][con_counter].nosql_type = RIAK;
        TRANSFER_ACTIONS[counter][con_counter] = START;

    } else if (0 == strcmp(globals.routes[counter].router, "esearch")) {
        if (!ensure_module_is_enabled("esearch")) {
            return false;
        }
        esearch_fd[counter][con_counter] = init_esearch_module(counter, con_counter);
        if (NULL == esearch_fd[counter][con_counter].cp) {
            Writeline(active_connections[counter][con_counter].connfd, NOT_APPLICABLE_ROUTE, strlen(NOT_APPLICABLE_ROUTE));
            killClient(counter, con_counter);
            return false;
        }
        handles[counter][con_counter].nosql_type = ESEARCH;
        TRANSFER_ACTIONS[counter][con_counter] = START;

    } else if (0 == strcmp(globals.routes[counter].router, "webhdfs")) {
        if (!ensure_module_is_enabled("webhdfs")) {
            return false;
        }
        if (!buffer) {
            webhdfs_fd[counter][con_counter] = init_webhdfs_module(counter, con_counter);
            if (NULL == webhdfs_fd[counter][con_counter].fd) {
                Writeline(active_connections[counter][con_counter].connfd, NOT_APPLICABLE_ROUTE, strlen(NOT_APPLICABLE_ROUTE));
                killClient(counter, con_counter);
                return false;
            }
        }
        handles[counter][con_counter].nosql_type = WEBHDFS;
        TRANSFER_ACTIONS[counter][con_counter] = START;

    }
    return true;
}

/**
 *
 * @param ip
 */
void close_descriptor(int rc, int con_counter) {

    if (0 == strcmp(globals.routes[rc].router, "plain")) {
        if (handles[rc][con_counter].type == SNAPPY) {
            close_snappy_file(rc, con_counter);
        } else if (handles[rc][con_counter].type == GZIP) {
            close_gzip_file(rc, con_counter);
        } else if (handles[rc][con_counter].type == NONE) {
            close_plain_file(rc, con_counter);
        }
        TRANSFER_ACTIONS[rc][con_counter] = UNINITIALIZED;
    } else {

        if (handles[rc][con_counter].nosql_type == RIAK) {
            if (!ensure_module_is_enabled("riak")) {
                return;
            }
            TRANSFER_ACTIONS[rc][con_counter] = UNINITIALIZED;
        }/* RIAK */

        if (handles[rc][con_counter].nosql_type == ESEARCH) {
            if (!ensure_module_is_enabled("esearch")) {
                return;
            }
            TRANSFER_ACTIONS[rc][con_counter] = UNINITIALIZED;
        }/* ESEARCH */

        if (handles[rc][con_counter].nosql_type == WEBHDFS) {
            if (!ensure_module_is_enabled("webhdfs")) {
                return;
            }
            close_webhdfs(rc, con_counter);
            TRANSFER_ACTIONS[rc][con_counter] = UNINITIALIZED;
        }/* WEBHDFS */

        if ((!globals.routes[rc].is_active && globals.routes[rc].buffering) || handles[rc][con_counter].nosql_type == BUFFER) {
            close_buffer(rc, con_counter);
            TRANSFER_ACTIONS[rc][con_counter] = UNINITIALIZED;
        }

    } /* nosql */

}

int has_applicable_route(char *ip) {

    int sz = 50;
    char func_msg[sz];
    static int msgc[ROUTES_MAX_COUNT];
    int cno = find_proper_router_counter(ip);
    if (-1 == cno) {
        if (msgc[cno] < 1) {
            snprintf(func_msg, sz, "No route found for address %s", ip);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(func_msg);
            pthread_mutex_unlock(&t_error);
            msgc[cno]++;
        }
        return -1;
    }

    if (is_route_disabled(cno)) {
        if (msgc[cno] < 1) {
            snprintf(func_msg, sz, "Route disabled for source address %s", ip);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(func_msg);
            pthread_mutex_unlock(&t_error);
            msgc[cno]++;
        }
        return -1;
    }

    if (!globals.routes[cno].is_active && !globals.routes[cno].buffering) {
        return -1;
    }
    return cno;
}

/**
 *
 * @param ip
 * @return
 */
bool is_route_absent(char *ip) {
    int router_id = find_proper_router(ip);
    return (-1 == router_id);
}

bool ensure_module_is_enabled(char *module) {
    int sz = strlen(DISABLED_MODULE) + strlen(module) + 20;
    char msg[sz];
    if (is_disabled_module(module)) {
        snprintf(msg, sz, "%s [ %s ]", DISABLED_MODULE, module);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(msg);
        pthread_mutex_unlock(&t_error);
        return false;
    }
    return true;
}

/**
 *
 * @param module
 * @return
 */
bool is_disabled_module(char *module) {
    int i;
    for (i = 0; i < MODULES_MAX_COUNT; i++) {
        if (0 == strcmp(globals.modules[i].name, module)) {
            return (!globals.modules[i].enabled);
        }
    }
    return false;
}

/**
 *
 * @param router
 * @param dst
 * @param data
 * @param rid
 */
int call_module(char *router, char *dst, char *data, int rc, int con_counter) {

    int sz = 100;
    char func_msg[sz];
    int i, counter = rc;
    bool ret = false;
    static int msgc[MODULES_MAX_COUNT] = {0, 0, 0, 0};

    for (i = 0; i < MODULES_MAX_COUNT; i++) {

        if (0 == strcmp(globals.modules[i].name, router)) {

            if (globals.modules[i].enabled == true) {

                if (globals.routes[counter].is_active) {
                    if (0 == strcasecmp(globals.routes[counter].router, "webhdfs") && NULL == webhdfs_fd[counter][con_counter].fd) {
                        if (TRANSFER_ACTIONS[counter][con_counter] == START) {
                            init_descriptor(counter, con_counter);
                        }
                    }
                    if (0 == strcasecmp(globals.routes[counter].router, "riak") && NULL == riak_fd[counter][con_counter].cp) {
                        if (TRANSFER_ACTIONS[counter][con_counter] == START) {
                            init_descriptor(counter, con_counter);
                        }
                    }
                    if (0 == strcasecmp(globals.routes[counter].router, "esearch") && NULL == esearch_fd[counter][con_counter].cp) {
                        if (TRANSFER_ACTIONS[counter][con_counter] == START) {
                            init_descriptor(counter, con_counter);
                        }
                    }
                    if (0 == strcasecmp(globals.routes[counter].router, "plain") && NULL == plain_fd[counter][con_counter]) {
                        if (TRANSFER_ACTIONS[counter][con_counter] == START) {
                            init_descriptor(counter, con_counter);
                        }
                    }

                    if (TRANSFER_ACTIONS[counter][con_counter] == START) {
                        ret = globals.modules[i].process_function(data, dst, counter, con_counter);
                    }
                    return ret;

                } else {
                    if (globals.routes[counter].buffering) {
                        if (NULL == buffer_fd[counter][con_counter]) {
                            init_descriptor(counter, con_counter);
                        }
                        return write_to_buffer(counter, con_counter, data); /**/
                    }
                }

            } else {
                if (msgc[i] < 1) {

                    snprintf(func_msg, sz, "Calling disabled module [ %s ]", globals.modules[i].name);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(func_msg);
                    pthread_mutex_unlock(&t_error);
                    msgc[i]++;
                }

            }
            break;
        }
    }

    return false;
}

/**
 *
 * @param ip
 * @return
 */
int find_proper_router(char *ip) {
    int i, j;
    int a, b, c, d, last_octet;
    char new_ip[16];

    for (i = 0; i < globals.routes_cnt; i++) {
        if (!globals.routes[i].enabled)continue;
        for (j = 0; j < SOURCE_IPNETCNT_PER_ROUTE; j++) {
            /* case we have a hostname */
            if (0 == strcmp(globals.routes[i].from[j].netmask, "") && globals.routes[i].from[j].lastoctet_range == 0) {
                if (0 == strcmp(globals.routes[i].from[j].address, ip)) {
                    return globals.routes[i].id;
                }
            } else
                /* case we have an ip range */
                if (0 == strcmp(globals.routes[i].from[j].netmask, "") && globals.routes[i].from[j].lastoctet_range != 0) {
                if (sscanf(globals.routes[i].from[j].address, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
                    for (last_octet = d; last_octet <= globals.routes[i].from[j].lastoctet_range; last_octet++) {
                        snprintf(new_ip, 16, "%d.%d.%d.%d", a, b, c, last_octet);
                        if (0 == strcmp(new_ip, ip)) {
                            return globals.routes[i].id;
                        }
                    }
                }
            } else
                /* case we have a subnet */
                if (0 != strcmp(globals.routes[i].from[j].netmask, "") && globals.routes[i].from[j].lastoctet_range == 0) {
                if (IsIPInRange(ip, globals.routes[i].from[j].address, globals.routes[i].from[j].netmask)) {

                    return globals.routes[i].id;
                }
            }
        }
    }
    return -1;
}

int find_proper_router_counter(char *ip) {
    int i, j;
    int a, b, c, d, last_octet;
    char new_ip[16];

    for (i = 0; i < globals.routes_cnt; i++) {
        if (!globals.routes[i].enabled)continue;
        for (j = 0; j < SOURCE_IPNETCNT_PER_ROUTE; j++) {

            /* case we have a hostname */
            if (0 == strcmp(globals.routes[i].from[j].netmask, "") && globals.routes[i].from[j].lastoctet_range == 0) {
                if (0 == strcmp(globals.routes[i].from[j].address, ip)) {
                    return i;
                }
            }
            /* case we have an ip range */
            if (0 == strcmp(globals.routes[i].from[j].netmask, "") && globals.routes[i].from[j].lastoctet_range != 0) {
                if (sscanf(globals.routes[i].from[j].address, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
                    for (last_octet = d; last_octet <= globals.routes[i].from[j].lastoctet_range; last_octet++) {
                        snprintf(new_ip, 16, "%d.%d.%d.%d", a, b, c, last_octet);
                        if (0 == strcmp(new_ip, ip)) {
                            return i;
                        }
                    }
                }
            }
            /* case we have a subnet */
            if (0 != strcmp(globals.routes[i].from[j].netmask, "") && globals.routes[i].from[j].lastoctet_range == 0) {
                if (IsIPInRange(ip, globals.routes[i].from[j].address, globals.routes[i].from[j].netmask)) {

                    return i;
                }
            }




        }
    }
    return -1;
}

/**
 *
 * @param id
 * @return
 */
int is_route_disabled(int rc) {

    return (false == globals.routes[rc].enabled);
}

/**
 *
 * @param id
 * @return
 */
char * get_router_to(int id) {
    int i;
    for (i = 0; i < globals.routes_cnt; i++) {

        if (id == globals.routes[i].id) {

            return globals.routes[i].to;
        }
    }
    return NULL;
}

/**
 *
 * @param id
 * @return
 */
char * get_router_from(int rc) {
    int i;
    for (i = 0; i < globals.routes_cnt; i++) {

        if (rc == i) {

            return globals.routes[i].from[0].address;
        }
    }
    return NULL;
}

/**
 *
 * @param dst
 * @return
 */
int get_routerc_by_dst(char *dst) {
    int i;
    for (i = 0; i < globals.routes_cnt; i++) {

        if (0 == strcmp(globals.routes[i].to, dst)) {

            return i;
        }
    }
    return -1;
}

int get_routerc_by_nn(char *nn) {
    int i;
    if (NULL == nn || 0 == strcmp(nn, "")) {
        return -1;
    }
    for (i = 0; i < globals.routes_cnt; i++) {
        if (0 == strcmp(globals.routes[i].namenode1, nn) || 0 == strcmp(globals.routes[i].namenode2, nn)) {

            return i;
        }
    }
    return -1;
}

/**
 *
 * @param id
 * @return
 */
char * get_router_name(int id) {
    int i;
    for (i = 0; i < globals.routes_cnt; i++) {

        if (id == globals.routes[i].id) {

            return globals.routes[i].router;
        }
    }
    return NULL;
}

/**
 *
 * @param id
 * @return
 */
int get_router_counter(int id) {
    int i;
    for (i = 0; i < globals.routes_cnt; i++) {
        if (id == globals.routes[i].id) {

            return i;
        }
    }
    return -1;
}

/**
 *
 * @param mname
 */
void enableModule(char *mname) {

    int i;
    for (i = 0; i < MODULES_COUNT; i++) {
        if (0 == strcmp(globals.modules[i].name, mname)) {

            globals.modules[i].enabled = true;
        }
    }
}

bool module_exists(char *module) {

    int i = 0;
    for (; i < MODULES_COUNT; i++) {
        if (0 == strcasecmp(globals.modules[i].name, module)) {

            return true;
        }
    }
    return false;
}

/**
 *
 * @param compressor
 * @return
 */
int get_compressor(const char *compressor) {
    if (compressor == NULL)return -1;

    int i;
    for (i = 0; i < COMPRESSORS_CNT; i++) {
        if (0 == strcmp(compressor, compressors_table[i])) {

            return i;
        }
    }
    return -1;
}

char *strip_chars(char *string, char *chars) {
    char * newstr = xmalloc(strlen(string) + 1);
    int counter = 0;

    for (; *string; string++) {
        if (!strchr(chars, *string)) {
            newstr[ counter ] = *string;
            ++counter;
        }
    }

    newstr[counter] = 0;

    return newstr;
}

bool is_int(double x) {

    return ((x * 2) / 2 == x);
}

char * str_replace(const char *string, const char *substr, const char *replacement) {
    char *tok = NULL;
    char *newstr = NULL;

    tok = strstr(string, substr);
    if (tok == NULL) return strdup(string);
    newstr = xmalloc(strlen(string) - strlen(substr) + strlen(replacement) + 1);
    if (newstr == NULL) return NULL;
    memcpy(newstr, string, tok - string);
    memcpy(newstr + (tok - string), replacement, strlen(replacement));
    memcpy(newstr + (tok - string) + strlen(replacement), tok + strlen(substr), strlen(string) - strlen(substr) - (tok - string));
    memset(newstr + strlen(string) - strlen(substr) + strlen(replacement), 0, 1);

    return newstr;
}

bool mkPath(char *path) {
    if (NULL == path) {
        return false;
    }

    int ret;
    char * new_path = xmalloc(strlen(path) * sizeof (char));
    char * tmp_path = xmalloc(strlen(path) * sizeof (char));
    strcpy(new_path, path);
    strcpy(tmp_path, "/");

    char * p;
    p = strtok(new_path, "/");
    if (NULL == p) {
        return false;
    }
    while (p != NULL) {
        strcat(tmp_path, p);
        if (!DirectoryExists(tmp_path)) {
            if (0 > (ret = mkdir(tmp_path, 0744) && ret != EEXIST)) {

                return false;
            }
        }
        strcat(tmp_path, "/");
        p = strtok(NULL, "/");

    }
    return true;
}
//

bool prepareLocalPath(char *path) {
    if (NULL == path) {

        return false;
    }
    return mkPath(path);
}

bool isLikeUrl(char *str) {
    if (NULL == str) {
        return false;
    }
    if (NULL != strstr(str, "http://") || NULL != strchr(str, ':')) {

        return true;
    }
    return false;
}

void * xmalloc(size_t size) {
    void *new_mem = (void *) malloc(size);

    if (new_mem == NULL) {

        fprintf(stderr, "Cannot allocate memory... Dying\n");
        exit(EXIT_FAILURE);
    }

    return new_mem;
}

void * xrealloc(void *ptr, size_t size) {
    void *new_mem = (void *) realloc(ptr, size);

    if (new_mem == NULL) {

        fprintf(stderr, "Cannot allocate memory... Dying\n");
        exit(EXIT_FAILURE);
    }

    return new_mem;
}

void * xcalloc(size_t nmemb, size_t size) {
    void *new_mem = (void *) calloc(nmemb, size);

    if (new_mem == NULL) {
        fprintf(stderr, "Cannot allocate memory... Dying\n");
        exit(EXIT_FAILURE);
    }

    return new_mem;
}
