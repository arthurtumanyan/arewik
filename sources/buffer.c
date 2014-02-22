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

/**
 *
 */
int scan_buffer_dir(const char *fpath, const struct stat *sb, int tflag) {

    int counter = 0;
    char *rid = NULL, *cid = NULL, *bpid = NULL, *zip = NULL, *timestamp = NULL;
    int sz = PATH_MAX + 30;
    char buffer_msg[sz];
    char filename[PATH_MAX];

    //
    if (FTW_F == tflag) {
        snprintf(filename, PATH_MAX, "%s", fpath);
        strtok((char *) fpath, "_");
        rid = strtok(NULL, "_");
        cid = strtok(NULL, "_");
        bpid = strtok(NULL, "_");
        zip = strtok(NULL, "_");
        timestamp = strtok(NULL, "_");
        //
        //
        if ((0 != strcmp(rid, "")) && (0 != strcmp(cid, "")) && (0 != strcmp(bpid, "")) && (0 != strcmp(zip, "")) && (0 != strcmp(timestamp, ""))) {
            counter = get_router_counter(atoi(rid));
            // if connection is active, there is no another connections related to
            // the specified route and buffer dumping is not in process
            if (globals.routes[counter].is_active && globals.routes[counter].enabled && globals.routes[counter].buffering) {
                //
                if (dump_buffer(atoi(rid), atoi(cid), atoi(zip), filename, globals.maxcon, atol(timestamp))) {
                    snprintf(buffer_msg, sz, "Dumping buffer %s done", filename);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(buffer_msg);
                    pthread_mutex_unlock(&t_error);
                    delete_buffer(filename);
                    //
                }
            }
        }
    }
    return 0;
}

/**
 *
 * @param buffer
 * @return
 */
FILE * open_buffer_file(char *buffer) {

    if (NULL == buffer)return NULL;
    int sz = PATH_MAX + 100;
    char buffer_msg[sz];
    FILE * ret;

    if (0 == get_file_size(buffer)) {
        snprintf(buffer_msg, sz, "%s", "Removing empty buffer file");
        writeToDebugLog(buffer_msg);
        delete_buffer(buffer);
        return NULL;
    }
    //
    if ((ret = fopen(buffer, "rb")) == NULL) {
        snprintf(buffer_msg, sz, "Cannot open file '%s' - %s\n", buffer, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(buffer_msg);
        pthread_mutex_unlock(&t_error);
        return NULL;
    } else {
        return ret;
    }

}

/**
 *
 * @param router
 * @param zip
 * @param bf
 * @param con_counter
 * @return
 */
bool dump_buffer(int rid, int cid, int zip, char *bf, int con_counter, time_t timestamp) {

    FILE *b;
    char DBUFFER[MAXLINE];
    bzero(DBUFFER, MAXLINE);
    int rc = get_router_counter(rid);
    init_nosql_connections(rid, rc, con_counter, true);

    if (NULL != (b = open_buffer_file(bf))) {

        while (NULL != fgets(DBUFFER, MAXLINE, b)) {
            /**
             * process_NOSQL
             */

            if (handles[rc][con_counter].nosql_type == ESEARCH) {
                process_esearch(DBUFFER, globals.routes[rc].to, rc, con_counter);
            }
            if (handles[rc][con_counter].nosql_type == RIAK) {
                process_riak(DBUFFER, globals.routes[rc].to, rc, con_counter);
            }

            /* if webhdfs */
            if (handles[rc][con_counter].nosql_type == WEBHDFS) {
                return upload_buffer_file(b, rc, cid, timestamp);
            }
        }

        fclose(b); /* close local file */
        /* close remote file */
        // close NOSQL

        if (handles[rc][con_counter].nosql_type == WEBHDFS) {
            close_webhdfs(rc, con_counter);
        }
        return true;
    }
    //
    return false;
}

/**
 *
 * @param buffer
 */
void delete_buffer(char *buffer) {
    if (NULL == buffer)return;
    int sz = PATH_MAX + 50;
    char buffer_msg[sz];

    if (-1 == remove(buffer)) {
        snprintf(buffer_msg, sz, "Can not remove buffer: %s ,%s", buffer, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToDebugLog(buffer_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        snprintf(buffer_msg, sz, "Removed buffer file: %s", buffer);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(buffer_msg);
        pthread_mutex_unlock(&t_error);
    }
}

/**
 *
 * @param rc, cc
 * @return
 */
FILE * open_buffer(int rc, int cc) {
    //
    time_t rawtime = time(NULL);
    char * parsed = parsePathPrefix(globals.routes[rc].dst_path_prefix, rc, cc);
    int p_size = strlen(arguments.bufferdir) + strlen(parsed) + 2;
    int sz = p_size + 80;
    char buffer_msg[sz];
    char file_name[PATH_MAX];
    char tmp_path[p_size];
    FILE * f;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    snprintf(tmp_path, p_size, "%s/%s", arguments.bufferdir, parsed);

    if (!prepareLocalPath(tmp_path)) {
        return NULL;
    }
    //
    snprintf(file_name, PATH_MAX, "%s/buffer_%d_%d_%d_%d_%ld", tmp_path, globals.routes[rc].id, cc, getpid(), globals.routes[rc].compressor, rawtime);
    if (FileExists(file_name)) {
        snprintf(file_name, PATH_MAX, "%s/buffer_%d_%d_%d_%d_%ld-%d", tmp_path, globals.routes[rc].id, cc, getpid(), globals.routes[rc].compressor, rawtime, get_rand());
    }
    if (NULL != (f = fopen(file_name, "wb"))) {
        snprintf(buffer_msg, sz + 50, "Opened file [%s] with handle No: %d for router %d", file_name, fileno(f), globals.routes[rc].id);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(buffer_msg);
        pthread_mutex_unlock(&t_error);
        files[rc][cc].filename = file_name;
        files[rc][cc].timestamp = time(NULL);
        TRANSFER_ACTIONS[rc][cc] = START;
        return f;
    }
    return NULL;

}

/**
 *
 * @param rc
 */
void close_buffer(int rc, int con_counter) {
    int sz = 80;
    char buffer_msg[sz];
    if (buffer_fd[rc][con_counter] != NULL && 0 < fileno(buffer_fd[rc][con_counter])) {
        snprintf(buffer_msg, sz, "Closing descriptor no %d", fileno(buffer_fd[rc][con_counter]));
        pthread_mutex_lock(&t_error);
        writeToDebugLog(buffer_msg);
        pthread_mutex_unlock(&t_error);
        if (0 != fclose(buffer_fd[rc][con_counter])) {
            snprintf(buffer_msg, sz, "An error accured: %s", strerror(errno));
            pthread_mutex_lock(&t_error);
            writeToCustomLog(buffer_msg);
            pthread_mutex_unlock(&t_error);
        }
    }
    buffer_fd[rc][con_counter] = NULL;

}

/**
 *
 * @param router_counter
 * @param data
 */
int write_to_buffer(int router_counter, int con_counter, char *data) {

    if (NULL != buffer_fd[router_counter][con_counter]) {
        if (globals.routes[router_counter].use_compression && globals.routes[router_counter].compressor == SNAPPY) {
            fwrite(compress_snappy(data, 0), sizeof (char), MAXLINE, buffer_fd[router_counter][con_counter]);
        } else {
            fprintf(buffer_fd[router_counter][con_counter], "%s", data);
        }
        fflush(buffer_fd[router_counter][con_counter]);
        scan_for_rotate(router_counter, con_counter);
        return true;
    }
    return false;
}

/**
 *
 */
void close_buffer_files() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            if (NULL != buffer_fd[i][j] && fileno(buffer_fd[i][j]) > 0) {
                fclose(buffer_fd[i][j]);
                buffer_fd[i][j] = NULL;
            }
        }
    }
}

/**
 *
 * @param bfile
 * @return
 */
bool is_processing(char *bfile) {
    int i;
    for (i = 0; i < globals.maxcon; i++) {
        if (0 == strcmp(in_process_buff[i].buffer, bfile)) {
            return true;
        }
    }
    return false;
}
