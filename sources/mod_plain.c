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
 * @param fname
 * @return 
 */
FILE * open_plain_file(char *fname, int counter, int con_counter) {
    time_t rawtime = time(NULL);
    char * parsed = parsePathPrefix(globals.routes[counter].dst_path_prefix, counter, con_counter);
    int p_size = strlen(arguments.storagedir) + strlen(parsed) + 2;
    int sz = p_size + 80;
    char plain_msg[sz];
    char plain_file[PATH_MAX];
    char tmp_path[p_size];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    snprintf(tmp_path, p_size, "%s/%s", arguments.storagedir, parsed);

    if (!prepareLocalPath(tmp_path)) {
        return NULL;
    }

    snprintf(plain_file, PATH_MAX, "%s/%ld.%s", tmp_path, rawtime, fname);
    if (FileExists(plain_file)) {
        snprintf(plain_file, PATH_MAX, "%s/%ld_%d.%s", tmp_path, rawtime, get_rand(), fname);
    }

    if (NULL != (plain_fd[counter][con_counter] = fopen(plain_file, "wb"))) {
        snprintf(plain_msg, sz, "Opened file [%s] with handle No: %d for router %d",
                plain_file, fileno(plain_fd[counter][con_counter]), globals.routes[counter].id);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(plain_msg);
        pthread_mutex_unlock(&t_error);
        files[counter][con_counter].filename = plain_file;
        files[counter][con_counter].timestamp = time(NULL);
        TRANSFER_ACTIONS[counter][con_counter] = START;
        return plain_fd[counter][con_counter];
    }
    return NULL;
}

/**
 * 
 */
void close_plain_files() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            if (NULL != plain_fd[i][j] && fileno(plain_fd[i][j]) > 0) {
                fclose(plain_fd[i][j]);
                plain_fd[i][j] = NULL;
            }
        }
    }
}

void close_plain_file(int rc, int cc) {
    int sz = 80;
    char plain_msg[sz];
    if ((NULL == plain_fd[rc][cc]) || (0 >= fileno(plain_fd[rc][cc])))return;
    snprintf(plain_msg, sz, "Closing descriptor no %d", fileno(plain_fd[rc][cc]));
    pthread_mutex_lock(&t_error);
    writeToDebugLog(plain_msg);
    pthread_mutex_unlock(&t_error);
    if (0 != fclose(plain_fd[rc][cc])) {
        snprintf(plain_msg, sz, "An error accured: %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToDebugLog(plain_msg);
        pthread_mutex_unlock(&t_error);
    }
    plain_fd[rc][cc] = NULL;
}

/**
 * 
 * @param pln_fd
 * @param data
 */
void write_plain(FILE *pln_fd, char * data) {

    if (NULL != pln_fd) {
        fprintf(pln_fd, "%s", data);
        fflush(pln_fd);
    }
}

/**
 * 
 * @param data
 * @param to
 * @param routerid
 * @param con_counter
 */
int process_plain(char * data, char *to, int counter, int con_counter) {

    if (counter == -1) {
        pthread_mutex_lock(&t_error);
        writeToDebugLog("process_plain(): counter = -1");
        pthread_mutex_unlock(&t_error);
        return 0;
    }

    if (true == globals.routes[counter].use_compression) {
        if (SNAPPY == globals.routes[counter].compressor) {
            write_snappy(snappy_fd[counter][con_counter], data);
        } else if (GZIP == globals.routes[counter].compressor) {
            write_gzip(gzip_fd[counter][con_counter], data);
        }
        scan_for_rotate(counter, con_counter);
        return 1;
    }
    write_plain(plain_fd[counter][con_counter], data);
    scan_for_rotate(counter, con_counter);
    return 1;

}
