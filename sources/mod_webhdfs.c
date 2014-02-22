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
#include "mod_webhdfs.h"
#include "htmlstreamparser.h"


void emptyBuf(int, int);
off_t getBufSize(FILE * fp);
FILE * initBuf(int, int);
int query_namenode(char *node_path);
void set_curl_main_opts(CURL *hnd);
bool webhdfs_setowner(char *path, char *owner, char *group);
/******************************************************************************/
static FILE * **local_buffer; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
static FILE * **tmp_read_fd; //[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER];
HTMLSTREAMPARSER *hsp;
//

void init_webhdfs_arrays() {
    int i = 0, j = 0;

    local_buffer = xmalloc(globals.routes_cnt * sizeof (FILE **));
    for (i = 0; i < globals.routes_cnt; i++) {
        local_buffer[i] = xmalloc(globals.maxcon * sizeof (FILE **));
    }
    //   
    tmp_read_fd = xmalloc(globals.routes_cnt * sizeof (FILE **));
    for (i = 0; i < globals.routes_cnt; i++) {
        tmp_read_fd[i] = xmalloc(globals.maxcon * sizeof (FILE **));
    }

    i = 0;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            webhdfs_fd[i][j].fd = NULL;
        }
    }
}

void set_curl_main_opts(CURL *hnd) {

    curl_easy_setopt(hnd, CURLOPT_VERBOSE, false);
    curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, true);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, globals.identline);
    curl_easy_setopt(hnd, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, false);
    curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, false);
    curl_easy_setopt(hnd, CURLOPT_FRESH_CONNECT, false);
    curl_easy_setopt(hnd, CURLOPT_NOSIGNAL, true);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, true);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, fopen("/dev/null", "w"));
#if LIBCURL_VERSION_MINOR >= 25
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, true);
#endif
    curl_easy_setopt(hnd, CURLOPT_CONNECTTIMEOUT, CTIMEOUT);
}

static size_t parse_reply(void *buffer, size_t size, size_t nmemb, struct _active_node *an) {

    char *ptr = NULL;

    size_t realsize = size * nmemb, p;
    size_t tmpstrl = 0;
    char *tmpstr = NULL;
    for (p = 0; p < realsize; p++) {
        html_parser_char_parse(hsp, ((char *) buffer)[p]);
        if (html_parser_cmp_tag(hsp, "/h1", 3)) {
            if (html_parser_is_in(hsp, HTML_CLOSING_TAG)) {
                tmpstrl = html_parser_inner_text_length(hsp);
                tmpstr = html_parser_replace_spaces(html_parser_trim(html_parser_inner_text(hsp), &tmpstrl), &tmpstrl);
                tmpstr[tmpstrl] = '\0';
                ptr = strtok(tmpstr, " ");
                if (NULL != ptr) {
                    ptr = strtok(NULL, " ");
                    ptr = strtok(NULL, " ");
                }
                if (0 == strcmp("(active)", (NULL != ptr) ? ptr : "")) {
                    an->is_active = 1;
                } else if (0 == strcmp("(standby)", (NULL != ptr) ? ptr : "")) {
                    an->is_active = 0;
                } else {
                    an->is_active = -1;
                }
                break;
            }
        }
    }

    return realsize;
}

char * get_active_namenode(int rc) {

    int sz = 128;
    char webhdfs_msg[sz];

    char node1_health_url[NAME_MAX + 15] = {0};
    char node2_health_url[NAME_MAX + 15] = {0};

    snprintf(node1_health_url, NAME_MAX + 15, "%s/dfshealth.jsp", globals.routes[rc].namenode1);
    snprintf(node2_health_url, NAME_MAX + 15, "%s/dfshealth.jsp", globals.routes[rc].namenode2);

    snprintf(webhdfs_msg, sz, "Querying namenode(1)(%s) for router id[%d]", globals.routes[rc].namenode1, globals.routes[rc].id);
    pthread_mutex_lock(&t_error);
    writeToDebugLog(webhdfs_msg);
    pthread_mutex_unlock(&t_error);
    int node1status = query_namenode(node1_health_url);
    if (-1 != node1status) {
        if (1 == node1status) {
            pthread_mutex_lock(&t_error);
            writeToDebugLog("Namenode(1) is active");
            pthread_mutex_unlock(&t_error);
        } else if (0 == node1status) {
            pthread_mutex_lock(&t_error);
            writeToDebugLog("Namenode(1) is standby");
            pthread_mutex_unlock(&t_error);
        }
    } else {
        pthread_mutex_lock(&t_error);
        writeToDebugLog("Something wrong with namenode(1)... Expecting errors");
        pthread_mutex_unlock(&t_error);
    }

    int node2status = query_namenode(node2_health_url);
    if (-1 != node2status) {
        if (1 == node2status) {
            pthread_mutex_lock(&t_error);
            writeToDebugLog("Namenode(2) is active");
            pthread_mutex_unlock(&t_error);
        } else if (0 == node2status) {
            pthread_mutex_lock(&t_error);
            writeToDebugLog("Namenode(2) is standby");
            pthread_mutex_unlock(&t_error);
        }
    } else {
        pthread_mutex_lock(&t_error);
        writeToDebugLog("Something wrong with namenode(2)... Expecting errors");
        pthread_mutex_unlock(&t_error);
    }

    if ((0 == node1status && 0 == node2status) || (-1 == node1status && -1 == node2status)) {
        snprintf(webhdfs_msg, sz, "Neither namenode(1) nor namenode(2) is active");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(webhdfs_msg);
        pthread_mutex_unlock(&t_error);
        return NULL;
    } else if (node1status) {
        return globals.routes[rc].namenode1;
    } else if (node2status) {
        return globals.routes[rc].namenode2;
    }
    return NULL;
}

int query_namenode(char *node_path) {

    CURL *hnd;
    long int httpcode;
    char tag[6], val[128];

    hnd = curl_easy_init();
    hsp = html_parser_init();

    html_parser_set_tag_to_lower(hsp, 1);
    html_parser_set_tag_buffer(hsp, tag, sizeof (tag));
    html_parser_set_inner_text_buffer(hsp, val, sizeof (val) - 1);
    struct _active_node node;
    curl_easy_setopt(hnd, CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(hnd, CURLOPT_URL, node_path);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, parse_reply);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &node);
    curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, true);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, true);
    curl_easy_setopt(hnd, CURLOPT_NOSIGNAL, true);
    curl_easy_perform(hnd);
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &httpcode);

    if (hnd)curl_easy_cleanup(hnd);
    html_parser_cleanup(hsp);

    hnd = NULL;
    if (httpcode != 200) {
        return -1;
    }
    if (node.is_active) {
        return 1;
    }
    return 0;
}

_webhdfs_fd init_webhdfs_module(int rcounter, int con_counter) {

    int sz = 180, fileName_sz = 0, path_sz = 0;
    char webhdfs_msg[sz];

    CURLcode curl_res;
    long http_code;
    char * effective_url = NULL;

    char *fileName;
    char *path;

    time_t rawtime;
    rawtime = time(NULL);
    char rawtime_str[11];
    snprintf(rawtime_str, 11, "%ld", rawtime);

    webhdfs_fd[rcounter][con_counter]._MY_TO = parseWEBHDFSTo(rcounter);
    char *parsed_path = parsePathPrefix(globals.routes[rcounter].dst_path_prefix, rcounter, con_counter);
    //
    struct curl_slist *headers = NULL;
    char *hdr = xmalloc(sizeof (char) * 8);
    memset(hdr, 0, 8);
    strncpy(hdr, "Expect:", 8);
    headers = curl_slist_append(headers, hdr);

    int queried = 0;
again:

    if (0 == strncmp(webhdfs_fd[rcounter][con_counter]._MY_TO.active_namenode, "(null)", 6) || 0 == strcmp(webhdfs_fd[rcounter][con_counter]._MY_TO.active_namenode, "")) {
        if (!queried) {
            strcpy(webhdfs_fd[rcounter][con_counter]._MY_TO.active_namenode, get_active_namenode(rcounter));
            queried++;
            goto again;
        }
        snprintf(webhdfs_msg, sz, "%s", "Active namenode is not defined for WEBHDFS");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(webhdfs_msg);
        pthread_mutex_unlock(&t_error);
        return webhdfs_fd[rcounter][con_counter];
    }

    // defining remote file name
    if (globals.routes[rcounter].use_compression && globals.routes[rcounter].compressor == SNAPPY) {
        fileName_sz = (strlen(webhdfs_fd[rcounter][con_counter]._MY_TO.dst_path) + 18);
    } else {
        fileName_sz = (strlen(webhdfs_fd[rcounter][con_counter]._MY_TO.dst_path) + 11);
    }
    fileName = xmalloc(sizeof (char) * fileName_sz);
    memset(fileName, 0, fileName_sz);

    strcpy(fileName, webhdfs_fd[rcounter][con_counter]._MY_TO.dst_path);
    strcat(fileName, ".");
    strcat(fileName, rawtime_str);

    if (globals.routes[rcounter].use_compression && globals.routes[rcounter].compressor == SNAPPY) {
        strcat(fileName, ".snappy");
    }

    int psz = strlen(webhdfs_fd[rcounter][con_counter]._MY_TO.active_namenode) + strlen(WEBHDFS_ROOT) + strlen(parsed_path) + 1;
    char *t_path = xmalloc(sizeof (char) * psz);
    memset(t_path, '\0', psz);

    strcpy(t_path, webhdfs_fd[rcounter][con_counter]._MY_TO.active_namenode);
    strcat(t_path, WEBHDFS_ROOT);
    strcat(t_path, parsed_path);
    t_path[psz] = '\0';
    //
    if (!HadoopPathExists(t_path)) {
        if (!prepareRemotePath(t_path, rcounter)) {
            return webhdfs_fd[rcounter][con_counter];
        }
    }
    //
    psz += strlen(webhdfs_fd[rcounter][con_counter]._MY_TO.dst_path) + 20;
    char *t_path2 = xmalloc(sizeof (char) * psz);
    memset(t_path2, 0, psz);

    strcpy(t_path2, t_path);
    strcat(t_path2, webhdfs_fd[rcounter][con_counter]._MY_TO.dst_path);
    strcat(t_path2, ".");
    strcat(t_path2, rawtime_str);

    if (globals.routes[rcounter].use_compression && globals.routes[rcounter].compressor == SNAPPY) {
        strcat(t_path2, ".snappy");
    }

    char buffersize_str[10];
    memset(buffersize_str, 0, 10);
    snprintf(buffersize_str, 10, "%d", globals.routes[rcounter].buffersize);

    path_sz = (strlen(t_path) + strlen(fileName) + strlen(webhdfs_fd[rcounter][con_counter]._MY_TO.dst_user) + strlen(buffersize_str) + 34);
    path = xmalloc(sizeof (char) * path_sz);
    memset(path, 0, path_sz);

    strcpy(path, t_path);
    strcat(path, fileName);
    strcat(path, "?op=CREATE&user.name=");
    strcat(path, webhdfs_fd[rcounter][con_counter]._MY_TO.dst_user);
    strcat(path, "&buffersize=");
    strcat(path, buffersize_str);

    // if user is defined append username to the request
    webhdfs_fd[rcounter][con_counter].fd = curl_easy_init();

    if (NULL != webhdfs_fd[rcounter][con_counter].fd) {
        set_curl_main_opts(webhdfs_fd[rcounter][con_counter].fd);
        curl_easy_setopt(webhdfs_fd[rcounter][con_counter].fd, CURLOPT_URL, path);
        curl_easy_setopt(webhdfs_fd[rcounter][con_counter].fd, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(webhdfs_fd[rcounter][con_counter].fd, CURLOPT_HTTPHEADER, headers);
        //
        curl_res = curl_easy_perform(webhdfs_fd[rcounter][con_counter].fd);

        curl_easy_getinfo(webhdfs_fd[rcounter][con_counter].fd, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_getinfo(webhdfs_fd[rcounter][con_counter].fd, CURLINFO_EFFECTIVE_URL, &effective_url);

        if (curl_res != CURLE_OK || http_code >= 400) {

            snprintf(webhdfs_msg, sz, "Failed to open '%s' for writing - %s [HTTP code: %ld]", t_path2, curl_easy_strerror(curl_res), http_code);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(webhdfs_msg);
            pthread_mutex_unlock(&t_error);
            memset(webhdfs_fd[rcounter][con_counter].remoteFile, 0, PATH_MAX);
            webhdfs_fd[rcounter][con_counter].fd = NULL;

            return webhdfs_fd[rcounter][con_counter];

        } else if (http_code == 201) {
            //
            effective_url = str_replace(effective_url, "CREATE", "APPEND");
            //
            snprintf(webhdfs_msg, sz, "Opened '%s' for writing [HTTP code: %ld]", t_path2, http_code);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(webhdfs_msg);
            pthread_mutex_unlock(&t_error);
            snprintf(webhdfs_fd[rcounter][con_counter].remoteFile, PATH_MAX, "%s", path);
            snprintf(webhdfs_fd[rcounter][con_counter].pureUrl, PATH_MAX, "%s%s", t_path, fileName);
            snprintf(webhdfs_fd[rcounter][con_counter].backupUrl, PATH_MAX, "%s%s", parsed_path, fileName);
            snprintf(webhdfs_fd[rcounter][con_counter].url, strlen(effective_url) + 1, "%s", effective_url);
        }

    }

    snprintf(tmp_buf[rcounter][con_counter], NAME_MAX, "/tmp/%s_%d", fileName, get_rand());

    if (globals.routes[rcounter].send_data_by_block) {
        local_buffer[rcounter][con_counter] = initBuf(rcounter, con_counter);
    }
    TRANSFER_ACTIONS[rcounter][con_counter] = START;
    curl_slist_free_all(headers);

    FREE(hdr);
    FREE(path);
    FREE(t_path2);
    FREE(t_path);
    FREE(fileName);

    return webhdfs_fd[rcounter][con_counter];
}

void do_webhdfs_rotate(int counter, int con_counter) {

    int sz = 128;
    char webhdfs_msg[sz];
    char *pure_url = NULL;
    char *backup_url = NULL;

    char fmt[64], tstr[64];
    struct timeval tv;
    struct tm *tm;

    gettimeofday(&tv, NULL);
    if ((tm = localtime(&tv.tv_sec)) != NULL) {
        strftime(fmt, sizeof fmt, "%d_%b_%Y_%H_%M_%S", tm);
        snprintf(tstr, sizeof tstr, fmt, tv.tv_usec);
    }
    CURL * curl;
    long int http_code = 0;

    if (0 == strcmp(webhdfs_fd[counter][con_counter].pureUrl, "") || 0 == strcmp(webhdfs_fd[counter][con_counter].backupUrl, "")) {
        return;
    }

    int pure_url_sz = strlen(webhdfs_fd[counter][con_counter].pureUrl) + 1;
    pure_url = xmalloc(sizeof (char) * pure_url_sz);
    memset(pure_url,'\0', pure_url_sz);
    
    int backup_url_sz = strlen(webhdfs_fd[counter][con_counter].backupUrl) + 1;
    backup_url = xmalloc(sizeof (char) * backup_url_sz);
    memset(backup_url,'\0',backup_url_sz);
    
    strncpy(pure_url, webhdfs_fd[counter][con_counter].pureUrl, pure_url_sz -1);
    strncpy(backup_url, webhdfs_fd[counter][con_counter].backupUrl, backup_url_sz -1);

    int size = strlen(pure_url);
    size += strlen(backup_url);

    size += strlen(tstr);
    size += strlen(globals.routes[counter].dst_auth_user);
    size += 38;

    char *path = xmalloc(sizeof (char) * size);
    memset(path,'\0', size);
    
    strcpy(path, pure_url);
    strcat(path, "?op=RENAME&destination=");
    if (backup_url[0] != '/') {
        strcat(path, "/");
    }
    strcat(path, backup_url);
    strcat(path, "_");
    strcat(path, tstr);
    strcat(path, "&user.name=");
    strcat(path, globals.routes[counter].dst_auth_user);

    curl = curl_easy_init();
    set_curl_main_opts(curl);
    curl_easy_setopt(curl, CURLOPT_URL, path);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);


    if (http_code == 200) {
        snprintf(webhdfs_msg, sz, "Rotated successfully [%d][%d]", counter, con_counter);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(webhdfs_msg);
        pthread_mutex_unlock(&t_error);
    }

    FREE(path);
    FREE(pure_url);
    FREE(backup_url);

}

int process_webhdfs(char * data, char *to, int counter, int con_counter) {

    long http_code = 0;
    int sz = 255;
    off_t oSize = 0;
    char webhdfs_msg[sz];
    CURLcode curl_res;

    struct curl_slist *headers = NULL;
    char *hdr = NULL;
    /* ------------------------------------------------------------------------ */
    if (globals.routes[counter].send_data_by_block && (0 != strcmp(":AREWIK:^DUMP_BUFFER:$:", data))) {
        if (NULL == local_buffer[counter][con_counter]) {
            pthread_mutex_lock(&t_error);
            writeToDebugLog("pushToBuf error()\n");
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }
        fputs((globals.routes[counter].use_compression && globals.routes[counter].compressor == SNAPPY) ? compress_snappy(data, 0) : data, local_buffer[counter][con_counter]);
        //
        oSize = getBufSize(local_buffer[counter][con_counter]);

        if (oSize < globals.routes[counter].send_data_size) {
            return 1;
        }
    }
    //
    if (globals.routes[counter].send_data_by_block) {
        tmp_read_fd[counter][con_counter] = fopen(tmp_buf[counter][con_counter], "r");
        if (!tmp_read_fd[counter][con_counter]) {
            snprintf(webhdfs_msg, sz, "An internal error accured in '%s'", __FUNCTION__);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(webhdfs_msg);
            pthread_mutex_unlock(&t_error);
            ++stats[counter][con_counter].fe;
            if (stats[counter][con_counter].fe >= HALT_ON_IERROR_C) {
                snprintf(webhdfs_msg, sz, "Exceeded internal errors count: %d. Killing current connection", HALT_ON_IERROR_C);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(webhdfs_msg);
                pthread_mutex_unlock(&t_error);
                pthread_mutex_lock(&t_process_w);
                process_webhdfs(":AREWIK:^DUMP_BUFFER:$:", "", counter, con_counter);
                pthread_mutex_unlock(&t_process_w);
                killClient(counter, con_counter);
            }
            return 0;
        }
        hdr = xmalloc(sizeof (char) * 38);
        strcpy(hdr, "Content-Type: application/octet-stream");
        headers = curl_slist_append(headers, hdr);
        if (NULL == headers) {
            pthread_mutex_lock(&t_error);
            writeToDebugLog("Null header in process_webhdfs(). This should never happen\n");
            pthread_mutex_unlock(&t_error);
        }
        curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_READDATA, tmp_read_fd[counter][con_counter]);
        curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_SEEKDATA, tmp_read_fd[counter][con_counter]);
        curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_INFILESIZE_LARGE, (off_t) - 1);
        curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_UPLOAD, true);
        TRANSFER_ACTIONS[counter][con_counter] = PAUSE;
    } else {
        curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_POSTFIELDS, (globals.routes[counter].use_compression && globals.routes[counter].compressor == SNAPPY) ? compress_snappy(data, 0) : data);
    }
    curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_URL, webhdfs_fd[counter][con_counter].url);
    curl_easy_setopt(webhdfs_fd[counter][con_counter].fd, CURLOPT_HTTPHEADER, headers);

    if (NULL != webhdfs_fd[counter][con_counter].remoteFile && NULL != webhdfs_fd[counter][con_counter].fd) {

        curl_res = curl_easy_perform(webhdfs_fd[counter][con_counter].fd);
        if (NULL != tmp_read_fd[counter][con_counter]) {
            fclose(tmp_read_fd[counter][con_counter]);
            tmp_read_fd[counter][con_counter] = NULL;
        }

        curl_easy_getinfo(webhdfs_fd[counter][con_counter].fd, CURLINFO_RESPONSE_CODE, &http_code);
        // Check for errors
        if (curl_res != CURLE_OK || http_code >= 400) {

            if (http_code == 404) {

                snprintf(webhdfs_msg, sz, "Can not find remote file '%s' for appending. Creating a new one", webhdfs_fd[counter][con_counter].remoteFile);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(webhdfs_msg);
                pthread_mutex_unlock(&t_error);
                TRANSFER_ACTIONS[counter][con_counter] = PAUSE;
                //
                if (globals.routes[counter].send_data_by_block) {
                    temps = xmalloc(sizeof (char) * strlen(tmp_buf[counter][con_counter]));

                    strcpy(temps, tmp_buf[counter][con_counter]);
                    tempfd = tmp_read_fd[counter][con_counter];

                }
                curl_easy_cleanup(webhdfs_fd[counter][con_counter].fd);
                webhdfs_fd[counter][con_counter].fd = NULL;
cagain:
                webhdfs_fd[counter][con_counter] = init_webhdfs_module(counter, con_counter);
                if (webhdfs_fd[counter][con_counter].fd == NULL) {
                    ++stats[counter][con_counter].ie;
                    if (stats[counter][con_counter].ie >= REMOTE_FILE_CATTEMPTS) {
                        snprintf(webhdfs_msg, sz, "Exceeded remote connection initialization attempts count: %d. Killing current connection", REMOTE_FILE_CATTEMPTS);
                        pthread_mutex_lock(&t_error);
                        writeToDebugLog(webhdfs_msg);
                        pthread_mutex_unlock(&t_error);
                        killClient(counter, con_counter);
                    }
                    snprintf(webhdfs_msg, sz, "Waiting 3 seconds to try again. Attempt #%d",stats[counter][con_counter].ie);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(webhdfs_msg);
                    pthread_mutex_unlock(&t_error);
                    sleep(3);
                    goto cagain;
                }
                //
                if (globals.routes[counter].send_data_by_block) {

                    if (NULL != tmp_read_fd[counter][con_counter]) {
                        fclose(tmp_read_fd[counter][con_counter]);
                        tmp_read_fd[counter][con_counter] = NULL;
                    }
                    unlink(tmp_buf[counter][con_counter]);

                    snprintf(tmp_buf[counter][con_counter], NAME_MAX, "%s", temps);
                    if (temps) {
                        FREE(temps);
                        temps = NULL;
                    }
                    tmp_read_fd[counter][con_counter] = tempfd;
                    pthread_mutex_lock(&t_process_w);
                    process_webhdfs(":AREWIK:^DUMP_BUFFER:$:", "", counter, con_counter);
                    pthread_mutex_unlock(&t_process_w);

                }
                /* 404 */
                TRANSFER_ACTIONS[counter][con_counter] = START;
            } else {
                snprintf(webhdfs_msg, sz, "Failed to open '%s' on remote server for appending - %s [HTTP code: %ld]", webhdfs_fd[counter][con_counter].remoteFile, curl_easy_strerror(curl_res), http_code);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(webhdfs_msg);
                pthread_mutex_unlock(&t_error);
            }
        }
    }
    if (globals.routes[counter].send_data_by_block && (0 != strcmp(":AREWIK:^DUMP_BUFFER:$:", data))) {
        TRANSFER_ACTIONS[counter][con_counter] = PAUSE;
        emptyBuf(counter, con_counter);
        TRANSFER_ACTIONS[counter][con_counter] = START;
    }
    //
    if (NULL != tmp_read_fd[counter][con_counter]) {
        tmp_read_fd[counter][con_counter] = NULL;
    }
    TRANSFER_ACTIONS[counter][con_counter] = START;

    curl_slist_free_all(headers);
    FREE(hdr);

    return (http_code == 200 || http_code == 201);
}

bool upload_buffer_file(FILE *fd, int rc, int cc, time_t timestamp) {

    CURL *curl;
    CURLcode res;
    long http_code;
    struct stat file_info;
    char * op = "CREATE";
    bool append = false;
    static int failures[ROUTES_MAX_COUNT];
    int sz = 128, fileName_sz = 0, path_sz = 0;
    char webhdfs_msg[sz];

    WEBHDFS_TO _MY_TO;

    char *fileName;
    char *path; //[PATH_MAX];

    char rawtime_str[11];
    snprintf(rawtime_str, 11, "%ld", timestamp);

    double speed_upload, total_time;
    struct curl_slist *headers = NULL;
    char *hdr1 = NULL, *hdr2 = NULL, *hdr3 = NULL;

    _MY_TO = parseWEBHDFSTo(rc);
    char *parsed_path = parsePathPrefix(globals.routes[rc].dst_path_prefix, rc, cc);

    if (NULL == _MY_TO.active_namenode || !isLikeUrl(_MY_TO.active_namenode)) {
        return false;
    }
    if (!globals.routes[rc].enabled) {
        return false;
    }
    if (!fd) {
        return false;
    }
    /* to get the file size */
    if (fstat(fileno(fd), &file_info) != 0) {
        return false; /* can't continue */
    }
    //
    if (0 == strcmp(_MY_TO.dst_path, "")) {
        snprintf(webhdfs_msg, sz, "%s", "Invalid or empty destination path for WEBHDFS");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(webhdfs_msg);
        pthread_mutex_unlock(&t_error);
        return false;
    }

    if (globals.routes[rc].use_compression && globals.routes[rc].compressor == SNAPPY) {
        fileName_sz = (strlen(parsed_path) + strlen(_MY_TO.dst_path) + strlen(rawtime_str) + 9);
    } else {
        fileName_sz = (strlen(parsed_path) + strlen(_MY_TO.dst_path) + strlen(rawtime_str) + 2);
    }

    fileName = xmalloc(sizeof (char) * fileName_sz);
    memset(fileName, '\0', fileName_sz);

    strcpy(fileName, parsed_path);
    strcat(fileName, _MY_TO.dst_path);
    strcat(fileName, ".");
    strcat(fileName, rawtime_str);

    if (globals.routes[rc].use_compression && globals.routes[rc].compressor == SNAPPY) {
        strcat(fileName, ".snappy");
    }

    int psz = strlen(_MY_TO.active_namenode) + strlen(WEBHDFS_ROOT) + strlen(parsed_path) + 1;
    char * t_path = xmalloc(sizeof (char) * psz);
    memset(t_path, 0, psz);

    strcpy(t_path, _MY_TO.active_namenode);
    strcat(t_path, WEBHDFS_ROOT);
    strcat(t_path, parsed_path);
    //
    if (!prepareRemotePath(t_path, rc)) {
        return NULL;
    }

    psz += strlen(_MY_TO.dst_path) + 10;

    char *t_path2 = xmalloc(sizeof (char) * psz);
    memset(t_path2, 0, psz);

    strcpy(t_path2, t_path);
    strcat(t_path2, _MY_TO.dst_path);
    strcat(t_path2, ".");
    strcat(t_path2, rawtime_str);

    if (globals.routes[rc].use_compression && globals.routes[rc].compressor == SNAPPY) {
        strcat(t_path2, ".snappy");
    }
    t_path2[psz] = '\0';
    //check whether path exists
    if (HadoopPathExists(t_path2)) {
        op = "APPEND";
        append = true;
    }

    hdr1 = xmalloc(sizeof (char) * 38);
    memset(hdr1, 0, 38);
    strcpy(hdr1, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, hdr1);
    //
    hdr2 = xmalloc(sizeof (char) * 26);
    memset(hdr2, 0, 26);
    strcpy(hdr2, "Transfer-Encoding: chunked");
    headers = curl_slist_append(headers, hdr2);
    //
    hdr3 = xmalloc(sizeof (char) * 7);
    memset(hdr3, 0, 7);
    strcpy(hdr3, "Expect:");
    headers = curl_slist_append(headers, hdr3);
    //
    path_sz = (strlen(_MY_TO.active_namenode) + strlen(WEBHDFS_ROOT) + strlen(fileName) + strlen(op) + strlen(_MY_TO.dst_user) + 16);
    path = xmalloc(sizeof (char) * path_sz);
    memset(path, 0, path_sz);
    strcpy(path, _MY_TO.active_namenode);
    strcat(path, WEBHDFS_ROOT);
    strcat(path, fileName);
    strcat(path, "?op=");
    strcat(path, op);
    strcat(path, "&user.name=");
    strcat(path, _MY_TO.dst_user);
    //
    curl = curl_easy_init();
    if (curl) {

        /* upload to this place */

        curl_easy_setopt(curl, CURLOPT_URL, path);
        if (!append) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        } else {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        }
        set_curl_main_opts(curl);
        curl_easy_setopt(curl, CURLOPT_HEADER, true);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, true);
        curl_easy_setopt(curl, CURLOPT_READDATA, fd);
        curl_easy_setopt(curl, CURLOPT_SEEKDATA, fd);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) file_info.st_size);
        //
        res = curl_easy_perform(curl);
        //
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
        /* Check for errors */

        if (res != CURLE_OK || http_code >= 400) {

            if (failures[rc] < 3) {
                snprintf(webhdfs_msg, sz, "Request to [%s] failed: %s [HTTP code: %ld]\n", path, curl_easy_strerror(res), http_code);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(webhdfs_msg);
                pthread_mutex_unlock(&t_error);
                failures[rc]++;
            } else {
                snprintf(webhdfs_msg, sz, "Disabling buffering support for route [id: %d] till next reconfigure because of frequent failures while uploading", globals.routes[rc].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(webhdfs_msg);
                pthread_mutex_unlock(&t_error);
                globals.routes[rc].buffering = false;
            }

            curl_easy_cleanup(curl);
            return false;

        } else {
            snprintf(webhdfs_msg, sz, "Uploaded: %.3f bytes/sec during %.3f seconds\n", speed_upload, total_time);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(webhdfs_msg);
            pthread_mutex_unlock(&t_error);
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    if (headers != NULL) {
        curl_slist_free_all(headers);
    }

    FREE(path);
    FREE(hdr1);
    FREE(hdr2);
    FREE(hdr3);
    FREE(t_path2);
    FREE(t_path);
    FREE(fileName);

    return true;
}

bool webhdfs_mkdir(char *path, int rc) {
    CURL * curl;
    long int http_code = 0;
    int sz = strlen(path) + strlen(globals.routes[rc].dst_auth_user) + 22;
    char *dp = xmalloc(sizeof (char) * sz);

    strcpy(dp, path);
    strcat(dp, "?op=MKDIRS&user.name=");
    strcat(dp, globals.routes[rc].dst_auth_user);

    curl = curl_easy_init();
    set_curl_main_opts(curl);
    curl_easy_setopt(curl, CURLOPT_URL, dp);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    if (NULL != dp) {
        FREE(dp);
    }

    return (http_code == 200);
}

bool webhdfs_setowner(char *path, char *owner, char *group) {

    if (NULL == path || NULL == owner) {
        return false;
    }

    CURL * curl;
    long int http_code = 0;

    int sz = strlen(path) + 20;
    char *dp = xmalloc(sizeof (char) * sz);

    strcpy(dp, path);
    strcat(dp, "?op=SETOWNER&owner=");
    strcat(dp, owner);
    if (group) {
        sz += strlen(group) + 7;
        dp = xrealloc(dp, sizeof (char) * sz);

        strcat(dp, "&group=");
        strcat(dp, group);
    }
    dp[sz] = '\0';
    curl = curl_easy_init();
    set_curl_main_opts(curl);
    curl_easy_setopt(curl, CURLOPT_URL, dp);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (NULL != dp) {
        FREE(dp);
    }

    return (http_code == 200);
}

bool ping_webhdfs(char *ip, int port) {

    if (true == host_is_alive(ip, port)) {

        return true;
    }
    return false;
}

WEBHDFS_TO parseWEBHDFSTo(int counter) {

    WEBHDFS_TO rto;
    int acn_sz = 0, dstu_sz = 0, dst_p = 0;

    acn_sz = (1 + strlen(globals.active_namenode));
    rto.active_namenode = xmalloc(sizeof (char) * acn_sz);
    memset(rto.active_namenode, 0, acn_sz);
    //
    dstu_sz = (0 != strcmp(globals.routes[counter].dst_auth_user, "") ? (1 + strlen(globals.routes[counter].dst_auth_user)) : 7);
    rto.dst_user = xmalloc(sizeof (char) * dstu_sz);
    memset(rto.dst_user, 0, dstu_sz);
    //
    dst_p = (strlen(globals.routes[counter].dst_path) + 1);
    rto.dst_path = xmalloc(1 + (sizeof (char) * dst_p));
    memset(rto.dst_path, 0, dst_p);

    strncpy(rto.active_namenode, globals.active_namenode, acn_sz);
    strncpy(rto.dst_user, (0 != strcmp(globals.routes[counter].dst_auth_user, "")) ? globals.routes[counter].dst_auth_user : "dr.who", dstu_sz);
    strncpy(rto.dst_path, globals.routes[counter].dst_path, dst_p);

    return rto;
}

void close_webhdfs(int rc, int con_counter) {
    TRANSFER_ACTIONS[rc][con_counter] = PAUSE;

    if (webhdfs_fd[rc][con_counter].fd) {

        if (0 < get_file_size(tmp_buf[rc][con_counter]) && globals.routes[rc].send_data_by_block) {
            pthread_mutex_lock(&t_process_w);
            process_webhdfs(":AREWIK:^DUMP_BUFFER:$:", "", rc, con_counter);
            pthread_mutex_unlock(&t_process_w);
            curl_easy_cleanup(webhdfs_fd[rc][con_counter].fd);
            webhdfs_fd[rc][con_counter].fd = NULL;
            if (NULL != local_buffer[rc][con_counter]) {
                fclose(local_buffer[rc][con_counter]);
                local_buffer[rc][con_counter] = NULL;
                unlink(tmp_buf[rc][con_counter]);
            }

        }

        if (NULL != tmp_read_fd[rc][con_counter]) {
            fclose(tmp_read_fd[rc][con_counter]);
        }
        if (FileExists(tmp_buf[rc][con_counter])) {
            unlink(tmp_buf[rc][con_counter]);
        }

        memset(webhdfs_fd[rc][con_counter].backupUrl, 0, PATH_MAX);
        memset(webhdfs_fd[rc][con_counter].pureUrl, 0, PATH_MAX);
        memset(webhdfs_fd[rc][con_counter].remoteFile, 0, PATH_MAX);
        memset(webhdfs_fd[rc][con_counter].url, 0, PATH_MAX);


        char * webhdfs_msg = "WEBHDFS handle cleaned";
        pthread_mutex_lock(&t_error);
        writeToDebugLog(webhdfs_msg);
        pthread_mutex_unlock(&t_error);

    }
}

void close_webhdfs_handles() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++)
            if (handles[i][j].nosql_type == WEBHDFS) {

                close_webhdfs(i, j);
            }
    }
}

bool prepareRemotePath(char *path, int rc) {

    if (NULL == path) {
        return false;
    }
    bool ret;
    int path_sz = strlen(path) + 1;
    char *new_path = strdup(path);

    char * url = xmalloc(sizeof (char) * path_sz);
    char * full_path = xmalloc(sizeof (char) * (path_sz + 1));
    memset(url, '\0', path_sz);
    memset(full_path, '\0', path_sz + 1);

    char * p = NULL, *saveptr = NULL;

    if (NULL != (p = strtok_r(new_path, "/", &saveptr))) {
        strcat(url, p);
        strcat(url, "//");
    } else return false;

    if (NULL != (p = strtok_r(NULL, "/", &saveptr))) {
        strcat(url, p);
        strcat(url, "/");
    } else return false;

    if (NULL != (p = strtok_r(NULL, "/", &saveptr))) {
        strcat(url, p);
        strcat(url, "/");
    } else return false;

    if (NULL != (p = strtok_r(NULL, "/", &saveptr))) {
        strcat(url, p);
    } else return false;

    strncpy(full_path, url, strlen(url));

    for (;;) {
        p = strtok_r(NULL, "/", &saveptr);

        if (p == NULL) {
            break;
        }

        if (full_path[strlen(full_path) - 1] != '/') {
            strcat(full_path, "/");
        }
        //
        strcat(full_path, p);
        //
        if (!HadoopPathExists(full_path)) {
            full_path[strlen(full_path)] = '\0';
            ret = webhdfs_mkdir(full_path, rc);
            if (!ret) {
                return ret;
            }
        }
        //
    }

    return true;
}

bool HadoopPathExists(char * path) {

    CURL * hnd = NULL;
    long int http_code = 0;

    if (NULL == path || 0 == strcmp(path, "")) {
        return false;
    }

    int sz = strlen(path) + 18;
    char *url = xmalloc(sizeof (char) * sz);
    memset(url, '\0', sz);
    strcpy(url, path);
    strcat(url, "?op=GETFILESTATUS");

    hnd = curl_easy_init();
    set_curl_main_opts(hnd);
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_perform(hnd);
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(hnd);
    FREE(url);
    return (http_code == 200);

}

void emptyBuf(int counter, int con_counter) {

    if (NULL != local_buffer[counter][con_counter]) {
        fclose(local_buffer[counter][con_counter]);
        local_buffer[counter][con_counter] = initBuf(counter, con_counter);

    }
}
//

off_t getBufSize(FILE * fp) {
    if (NULL == fp) {
        pthread_mutex_lock(&t_error);
        writeToDebugLog("getBufSize()\n");
        pthread_mutex_unlock(&t_error);
        exit(EXIT_FAILURE);
    }
    return get_file_size_by_hnd(fp);
}
//

FILE * initBuf(int counter, int con_counter) {
    FILE *tb = fopen(tmp_buf[counter][con_counter], "w");
    if (!tb) {
        char msg[64];
        snprintf(msg, 64, "Error: initBuf(), %s\n", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToDebugLog(msg);
        pthread_mutex_unlock(&t_error);
        exit(EXIT_FAILURE);
    }
    return (NULL != tb) ? tb : NULL;
}
