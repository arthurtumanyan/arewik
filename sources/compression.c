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
#include <snappy-c.h>

/**
 * 
 * @param data
 * @return 
 */
char * compress_snappy(char *data, int c) {
    static char output[MAXLINE];
    size_t input_length = strlen(data) + 1;
    size_t output_length = snappy_max_compressed_length(input_length);
    if (snappy_compress(data, input_length, output, &output_length) == SNAPPY_OK) {
        if (SNAPPY_OK == snappy_validate_compressed_buffer(output, output_length)) {
            return output;
        }
    }
    return NULL;
}

/**
 * 
 * @param data
 * @return 
 */
char * compress_bz2(char *data, int c) {
    return NULL;
}

/**
 * 
 * @param data
 * @return 
 */
char * compress_lzo(char * data, int c) {
    return NULL;
}

/**
 * 
 * @param data
 * @return 
 */
char * compress_gzip(char * data, int c) {
    static Bytef compressed[MAXLINE];
    uLong compressed_len = MAXLINE;
    uLong len = (uLong) strlen(data) + 1;
    compress2(compressed, &compressed_len, (const Bytef*) data, len, compression_ratio(c));
    return (char *) compressed;
}

/**
 * 
 * 
 * @param fname
 * @param rid
 * @return 
 */
FILE * open_snappy_file(char *fname, int counter, int con_counter) {
    //
    time_t rawtime = time(NULL);
    char * parsed = parsePathPrefix(globals.routes[counter].dst_path_prefix, counter, con_counter);
    int p_size = strlen(arguments.storagedir) + strlen(parsed) + 2;
    int sz = p_size + 80;
    char compress_msg[sz];
    char s_file[PATH_MAX];
    char tmp_path[p_size];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    snprintf(tmp_path, p_size, "%s/%s", arguments.storagedir, parsed);

    if (!prepareLocalPath(tmp_path)) {
        return NULL;
    }
    //
    snprintf(s_file, PATH_MAX, "%s/%ld.%s.snappy", tmp_path, rawtime, fname);

    if (FileExists(s_file)) {
        snprintf(s_file, PATH_MAX, "%s/%ld_%d.%s.snappy", tmp_path, rawtime, get_rand(), fname);
    }

    if (NULL != (snappy_fd[counter][con_counter] = fopen(s_file, "wb"))) {
        snprintf(compress_msg, sz, "Opened file [%s] with handle No: %d for router %d",
                s_file, fileno(snappy_fd[counter][con_counter]), globals.routes[counter].id);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(compress_msg);
        pthread_mutex_unlock(&t_error);
        files[counter][con_counter].filename = s_file;
        files[counter][con_counter].timestamp = time(NULL);
        TRANSFER_ACTIONS[counter][con_counter] = START;
        return snappy_fd[counter][con_counter];
    }

    return NULL;
}

/**
 * 
 * @param snp_fd
 * @param data
 */
void write_snappy(FILE *snp_fd, char *data) {

    if (NULL != snp_fd) {
        fwrite(compress_snappy(data, 0), sizeof (char), MAXLINE, snp_fd);
        fflush(snp_fd);
    }
}

/**
 * 
 */
void close_snappy_files() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            if (NULL == snappy_fd[i][j]) {
                continue;
            } else if (0 < fileno(snappy_fd[i][j])) {
                fclose(snappy_fd[i][j]);
                snappy_fd[i][j] = NULL;
            }
        }
    }
}

void close_snappy_file(int rc, int cc) {
    int sz = 80;
    char compress_msg[sz];
    if ((NULL == snappy_fd[rc][cc]) || (0 >= fileno(snappy_fd[rc][cc])))return;
    snprintf(compress_msg, sz, "Closing descriptor no %d", fileno(snappy_fd[rc][cc]));
    pthread_mutex_lock(&t_error);
    writeToDebugLog(compress_msg);
    pthread_mutex_unlock(&t_error);
    if (0 != fclose(snappy_fd[rc][cc])) {
        snprintf(compress_msg, sz, "An error accured: %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(compress_msg);
        pthread_mutex_unlock(&t_error);
    }
    snappy_fd[rc][cc] = NULL;

}

/**
 * 
 * @param fname
 * @param rid
 * @return 
 */
gzFile open_gzip_file(char *fname, int counter, int con_counter) {


    time_t rawtime = time(NULL);
    char * parsed = parsePathPrefix(globals.routes[counter].dst_path_prefix, counter, con_counter);
    int p_size = strlen(arguments.storagedir) + strlen(parsed) + 2;
    int sz = p_size + 80;
    char compress_msg[sz];
    char gzip_file[PATH_MAX];
    char tmp_path[p_size];
    char mode[4];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    snprintf(tmp_path, p_size, "%s/%s", arguments.storagedir, parsed);

    if (!prepareLocalPath(tmp_path)) {
        return NULL;
    }
    snprintf(gzip_file, PATH_MAX, "%s/%ld.%s.gzip", tmp_path, rawtime, fname);

    if (FileExists(gzip_file)) {
        snprintf(gzip_file, PATH_MAX, "%s/%ld_%d.%s.gzip", tmp_path, rawtime, get_rand(), fname);
    }

    snprintf(mode, 4, "w%dh", compression_ratio(counter));
    gzip_fd[counter][con_counter] = gzopen(gzip_file, mode);
    if (Z_NULL != gzip_fd[counter][con_counter]) {
        snprintf(compress_msg, sz, "Opened file [%s]:  for router %d",
                gzip_file, globals.routes[counter].id);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(compress_msg);
        pthread_mutex_unlock(&t_error);
    }
    files[counter][con_counter].filename = gzip_file;
    files[counter][con_counter].timestamp = time(NULL);
    TRANSFER_ACTIONS[counter][con_counter] = START;
    return gzip_fd[counter][con_counter];
}

/**
 * 
 */
void close_gzip_files() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            if (NULL != gzip_fd[i][j] && fileno((FILE *) gzip_fd[i][j]) > 0) {
                gzclose(gzip_fd[i][j]);
                gzip_fd[i][j] = Z_NULL;
            }
        }
    }
}

void close_gzip_file(int rc, int cc) {
    int sz = 80;
    char compress_msg[sz];
    if (Z_NULL == gzip_fd[rc][cc]) return;
    snprintf(compress_msg, sz, "Closing GZ descriptor");
    pthread_mutex_lock(&t_error);
    writeToDebugLog(compress_msg);
    pthread_mutex_unlock(&t_error);
    if (Z_OK != gzclose(gzip_fd[rc][cc])) {
        snprintf(compress_msg, sz, "%s", "Error accured with gzclose");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(compress_msg);
        pthread_mutex_unlock(&t_error);
    }
    gzip_fd[rc][cc] = Z_NULL;

}

/**
 * 
 * @param gzfd
 * @param data
 */
void write_gzip(gzFile gzfd, voidpc data) {
    if (Z_NULL != gzfd) {
        gzwrite(gzfd, data, strlen(data));
        gzflush(gzfd, Z_SYNC_FLUSH);
    }
}

