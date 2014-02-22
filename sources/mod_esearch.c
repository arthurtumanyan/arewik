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
#include "mod_esearch.h"

size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    return 0;
}

_esearch_fd init_esearch_module(int counter, int con_counter) {
    int sz = 256;
    char esearch_msg[PATH_MAX];


    esearch_fd[counter][con_counter].cp = curl_easy_init();
    if (NULL == esearch_fd[counter][con_counter].cp) {
        snprintf(esearch_msg, sz, "%s", "Could not initialize curl handle for ESEARCH");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(esearch_msg);
        pthread_mutex_unlock(&t_error);
        return esearch_fd[counter][con_counter];
    }
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_USERAGENT, globals.identline);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_SSL_VERIFYHOST, false);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_FORBID_REUSE, false);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_FRESH_CONNECT, false);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_NOSIGNAL, true);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_WRITEDATA, fopen("/dev/null", "w"));
#if LIBCURL_VERSION_MINOR >= 25
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_TCP_KEEPALIVE, true);
#endif
    curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_VERBOSE, false);

    TRANSFER_ACTIONS[counter][con_counter] = START;
    return esearch_fd[counter][con_counter];

}

int process_esearch(char * data, char *to, int counter, int con_counter) {
    int sz = 256;
    char esearch_msg[sz];
    long http_code = 0;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json; charset=UTF-8");
    CURLcode curl_res;
    ESEARCH_TO _MY_TO;
    _MY_TO = parseESEARCHTo(to);
    //
    if (NULL == to) {
        return 0;
    }
    //
    if (0 == strcmp(_MY_TO.dst_ip, "")) {
        snprintf(esearch_msg, sz, "%s", "Invalid or empty destination address for ESEARCH");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(esearch_msg);
        pthread_mutex_unlock(&t_error);
        return 0;
    }
    snprintf(esearch_fd[counter][con_counter].url, PATH_MAX, "%s://%s:%d/%s/%s/%s", _MY_TO.proto, _MY_TO.dst_ip, _MY_TO.dst_port, parsePathPrefix(globals.routes[counter].index_name, counter, con_counter), parsePathPrefix(globals.routes[counter].type_name, counter, con_counter), parsePathPrefix(globals.routes[counter].uniqueid, counter, con_counter));

    /* ------------------------------------------------------------------------ */
    trim(data);
    my_string = json_object_new_string(data);
    int psz = strlen(json_object_to_json_string(my_string)) + 21;
    char postdata[psz];
    snprintf(postdata, psz, "{ \"log_entry\" : %s }", json_object_to_json_string(my_string));
    json_object_put(my_string);
    if (NULL != esearch_fd[counter][con_counter].cp) {

        curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_URL, esearch_fd[counter][con_counter].url);
        curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_POSTFIELDS, postdata);
        curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) - 1);
        curl_easy_setopt(esearch_fd[counter][con_counter].cp, CURLOPT_HTTPHEADER, headers);
        curl_res = curl_easy_perform(esearch_fd[counter][con_counter].cp);

        curl_easy_getinfo(esearch_fd[counter][con_counter].cp, CURLINFO_RESPONSE_CODE, &http_code);
        // Check for errors
        if (curl_res != CURLE_OK || http_code >= 400) {
            snprintf(esearch_msg, sz, "Failed to open '%s' on remote server for appending - %s [HTTP code: %ld]", esearch_fd[counter][con_counter].url, curl_easy_strerror(curl_res), http_code);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(esearch_msg);
            pthread_mutex_unlock(&t_error);
        }
    }
    //
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    return (http_code == 200 || http_code == 201);
}

bool ping_esearch(char *ip, int port) {

    if (true == host_is_alive(ip, port)) {
        return true;
    }
    return false;
}

ESEARCH_TO parseESEARCHTo(char *to) {
    static ESEARCH_TO rto;
    char dst[CFG_PARAM_LEN];
    char *tmp;
    char *proto;
    char *ip, *tmp_ip;
    char *port;

    snprintf(dst, CFG_PARAM_LEN, "%s", to);
    bzero(rto.dst_ip, 16);
    bzero(rto.proto, 6);
    bzero(rto.index, 64);
    bzero(rto.type, 64);
    rto.dst_port = 0;

    int rc = get_routerc_by_dst(to);

    if (NULL == dst)return rto;
    if (NULL != strstr(dst, "http://") || NULL != strstr(dst, "https://")) {
        proto = strtok(dst, ":");
        tmp = strtok(NULL, ":");
    } else {
        proto = "http";
        tmp = strtok(dst, ":");
    }
    tmp_ip = strip_chars(tmp, "/");
    ip = nslookup(tmp_ip);

    if (NULL == ip) {
        return rto;
    }

    port = strtok(NULL, ":");
    if (!isValidPort(port)) {
        rto.dst_port = 0;
    } else {
        rto.dst_port = atoi(port);
    }

    snprintf(rto.proto, 5, "%s", proto);
    snprintf(rto.dst_ip, 16, "%s", ip);
    snprintf(rto.index, 64, "%s", globals.routes[rc].index_name);
    snprintf(rto.type, 64, "%s", globals.routes[rc].type_name);

    FREE(tmp_ip);

    return rto;
}

void close_esearch(int rc, int con_counter) {
    if (esearch_fd[rc][con_counter].cp) {
        curl_easy_cleanup(esearch_fd[rc][con_counter].cp);
        esearch_fd[rc][con_counter].cp = NULL;
        char * esearch_msg = "ESEARCH handle cleaned";
        pthread_mutex_lock(&t_error);
        writeToDebugLog(esearch_msg);
        pthread_mutex_unlock(&t_error);
    }

}

void close_esearch_handles() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++)
            if (handles[i][j].nosql_type == ESEARCH) {
                close_esearch(i, j);
            }
    }
}
